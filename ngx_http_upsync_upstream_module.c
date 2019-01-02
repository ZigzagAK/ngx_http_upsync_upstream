#include <ngx_core.h>

#include <ngx_http.h>
#include <ngx_inet.h>

#include "ngx_dynamic_upstream_module.h"
#include "ngx_http_send_request.h"


static void *
ngx_http_upsync_upstream_create_srv_conf(ngx_conf_t *cf);


static ngx_int_t
ngx_http_upsync_upstream_post_conf(ngx_conf_t *cf);


ngx_int_t
ngx_http_upsync_upstream_init_worker(ngx_cycle_t *cycle);


void
ngx_http_upsync_upstream_exit_worker(ngx_cycle_t *cycle);


typedef struct
{
    ngx_str_t      uri;
    ngx_array_t   *headers;
    ngx_msec_t     timeout;
    ngx_msec_t     interval;
    ngx_str_t      file;
    ngx_uint_t     hash;
    ngx_flag_t     busy;
    ngx_msec_t     last;
    ngx_url_t      url;

    ngx_http_upstream_srv_conf_t  *uscf;
} ngx_http_upsync_upstream_srv_conf_t;


static ngx_command_t ngx_http_upsync_upstream_commands[] = {

    { ngx_string("upsync"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upsync_upstream_srv_conf_t, uri),
      NULL },

    { ngx_string("upsync_timeout"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upsync_upstream_srv_conf_t, timeout),
      NULL },

    { ngx_string("upsync_interval"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upsync_upstream_srv_conf_t, interval),
      NULL },

    { ngx_string("upsync_header"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upsync_upstream_srv_conf_t, headers),
      NULL },

    { ngx_string("upsync_file"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upsync_upstream_srv_conf_t, file),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_upsync_upstream_ctx = {
    NULL,                                         /* preconfiguration */
    ngx_http_upsync_upstream_post_conf,           /* postconfiguration */
    NULL,                                         /* create main */
    NULL,                                         /* init main */
    ngx_http_upsync_upstream_create_srv_conf,     /* create server */
    NULL,                                         /* merge server */
    NULL,                                         /* create location */
    NULL                                          /* merge location */
};


ngx_module_t ngx_http_upsync_upstream_module = {
    NGX_MODULE_V1,
    &ngx_http_upsync_upstream_ctx,            /* module context */
    ngx_http_upsync_upstream_commands,        /* module directives */
    NGX_HTTP_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    ngx_http_upsync_upstream_init_worker,     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    ngx_http_upsync_upstream_exit_worker,     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_upsync_upstream_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_upsync_upstream_srv_conf_t  *uscf;

    uscf = ngx_pcalloc(cf->pool,
        sizeof(ngx_http_upsync_upstream_srv_conf_t));
    if (uscf == NULL)
        return NULL;

    uscf->timeout = NGX_CONF_UNSET_MSEC;
    uscf->interval = NGX_CONF_UNSET_MSEC;
    
    return uscf;
}


static ngx_int_t
ngx_http_upsync_sync_upstreams();


static void
ngx_http_upsync_sync_handler(ngx_event_t *ev)
{
    ngx_http_upsync_sync_upstreams();

    if (ngx_exiting || ngx_terminate || ngx_quit) {
        // cleanup
        ngx_memset(ev, 0, sizeof(ngx_event_t));
        return;
    }

    ngx_add_timer(ev, 1000);
}

static ngx_connection_t dumb_conn = {
    .fd = -1
};
static ngx_event_t sync_ev = {
    .handler = ngx_http_upsync_sync_handler,
    .data = &dumb_conn,
    .log = NULL
};


static FILE *
state_open(ngx_str_t *state_file)
{
    u_char            path[10240];
    FILE             *f;
    ngx_core_conf_t  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    if (ccf->working_directory.len != 0)
        ngx_snprintf(path, 10240, "%V/%V\0",
                     &ccf->working_directory, state_file);
    else
        ngx_snprintf(path, 10240, "%V", state_file);

    f = fopen((const char *) path, "w+");
    if (f == NULL)
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0, "can't open file: %s",
                      &path);

    return f;
}


static void
ngx_http_upsync_upstream_save(ngx_http_upsync_upstream_srv_conf_t *hscf)
{
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers, *primary;
    ngx_uint_t                     j = 0;
    u_char                         srv[10240], *c;
    FILE                          *f;
    ngx_str_t                      server;

    f = state_open(&hscf->file);
    if (f == NULL)
        return;

    primary = hscf->uscf->peer.data;
    
    ngx_rwlock_rlock(&primary->rwlock);

    for (peers = primary;
         peers && j < 2;
         peers = peers->next, j++) {

        ngx_str_null(&server);

        for (peer = peers->peer;
             peer;
             peer = peer->next) {

            if (ngx_memn2cmp(peer->server.data, server.data,
                             peer->server.len, server.len) != 0) {
                c = ngx_snprintf(srv, 10240,
                    "server %V max_conns=%d max_fails=%d fail_timeout=%d "
                    "weight=%d",
                    &peer->server, peer->max_conns, peer->max_fails,
                    peer->fail_timeout, peer->weight);
                fwrite(srv, c - srv, 1, f);
                if (j == 1)
                    fwrite(" backup", 7, 1, f);
                fwrite(";\n", 2, 1, f);
                server = peer->server;
            }
        }
    }

    ngx_rwlock_unlock(&primary->rwlock);

    fclose(f);
}


static ngx_uint_t count = 0;

static ngx_int_t
ngx_http_upsync_upstream_post_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_main_conf_t         *umcf;
    ngx_http_upstream_srv_conf_t         **uscf;
    ngx_http_upsync_upstream_srv_conf_t   *hscf;
    ngx_uint_t                             j;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    uscf = umcf->upstreams.elts;

    for (j = 0; j < umcf->upstreams.nelts; j++) {

        hscf = ngx_http_conf_upstream_srv_conf(uscf[j],
            ngx_http_upsync_upstream_module);

        if (hscf->uri.data == NULL || uscf[j]->shm_zone == NULL)
            continue;

        count++;

        hscf->uscf = uscf[j];
        hscf->url.url = hscf->uri;
        hscf->url.uri_part = 1;
        hscf->url.default_port = 80;

        if (ngx_parse_url(cf->pool, &hscf->url) != NGX_OK) {

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "http_upsync upstream: [%V] failed "
                          "to parse uri: %V", &hscf->uscf->host, &hscf->uri);
            return NGX_ERROR;
        }

        if (hscf->interval == NGX_CONF_UNSET_MSEC)
            hscf->interval = 60000;

        if (hscf->timeout == NGX_CONF_UNSET_MSEC)
            hscf->timeout = 10000;

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "http_upsync upstream: [%V] sync on", &hscf->uscf->host);
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_upsync_upstream_init_worker(ngx_cycle_t *cycle)
{
    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return NGX_OK;

    if (count != 0) {
        sync_ev.log = cycle->log;
        ngx_add_timer(&sync_ev, 0);
    }

    return NGX_OK;
}


void
ngx_http_upsync_upstream_exit_worker(ngx_cycle_t *cycle)
{
    if (sync_ev.log != NULL) {
        ngx_del_timer(&sync_ev);
        ngx_memset(&sync_ev, 0, sizeof(ngx_event_t));
    }
}


static ngx_flag_t
ngx_http_upsync_exists(ngx_http_upstream_rr_peers_t *primary,
    ngx_str_t *name)
{
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers;
    ngx_uint_t                     j = 0;

    ngx_rwlock_rlock(&primary->rwlock);

    for (peers = primary;
         peers && j < 2;
         peers = peers->next, j++) {

        for (peer = peers->peer;
             peer;
             peer = peer->next) {

            if (ngx_memn2cmp(peer->server.data, name->data,
                             peer->server.len, name->len) == 0) {
                ngx_rwlock_unlock(&primary->rwlock);
                return 1;
            }

            if (ngx_memn2cmp(peer->name.data, name->data,
                             peer->name.len, name->len) == 0) {
                ngx_rwlock_unlock(&primary->rwlock);
                return 1;
            }
        }
    }

    ngx_rwlock_unlock(&primary->rwlock);

    return 0;
}


static void
ngx_http_upsync_op_defaults(ngx_dynamic_upstream_op_t *op,
    ngx_str_t *upstream, ngx_str_t *server, ngx_str_t *name, int operation)
{
    ngx_memzero(op, sizeof(ngx_dynamic_upstream_op_t));

    op->op = operation;
    op->err = "unknown";

    op->status = NGX_HTTP_OK;
    op->down = 1;

    op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;

    op->server.data = server->data;
    op->server.len = server->len;

    if (name != NULL) {
        op->name.data = name->data;
        op->name.len = name->len;
    }

    op->upstream.data = upstream->data;
    op->upstream.len = upstream->len;
}


static void
ngx_http_upsync_op_defaults_locked(ngx_dynamic_upstream_op_t *op,
    ngx_str_t *upstream, ngx_str_t *server, ngx_str_t *name, int operation)
{
    ngx_http_upsync_op_defaults(op, upstream, server, name, operation);
    op->no_lock = 1;
}


static void
ngx_http_upsync_remove_obsoleted(ngx_http_upsync_upstream_srv_conf_t *hscf,
    ngx_array_t *names)
{
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers, *primary;
    ngx_uint_t                     j = 0;
    ngx_dynamic_upstream_op_t      op;
    ngx_str_t                     *elts;
    ngx_uint_t                     i;
    static ngx_str_t               noaddr = ngx_string("0.0.0.0:1");

    elts = names->elts;

    primary = hscf->uscf->peer.data;

    ngx_rwlock_wlock(&primary->rwlock);

    for (peers = primary;
         peers && j < 2;
         peers = peers->next, j++) {

        for (peer = peers->peer;
             peer;
             peer = peer->next) {

            for (i = 0; i < names->nelts; i++) {

                if (ngx_memn2cmp(peer->server.data, elts[i].data,
                                 peer->server.len, elts[i].len) == 0)
                    break;

                if (ngx_memn2cmp(peer->name.data, elts[i].data,
                                 peer->name.len, elts[i].len) == 0)
                    break;
            }

            if (i == names->nelts) {

again:

                ngx_http_upsync_op_defaults_locked(&op, &hscf->uscf->host,
                    &peer->server, &peer->name, NGX_DYNAMIC_UPSTEAM_OP_REMOVE);

                if (ngx_dynamic_upstream_op(ngx_cycle->log, &op, hscf->uscf)
                        == NGX_ERROR) {

                    if (op.status == NGX_HTTP_BAD_REQUEST) {

                        ngx_http_upsync_op_defaults_locked(&op,
                            &hscf->uscf->host, &noaddr, &noaddr,
                            NGX_DYNAMIC_UPSTEAM_OP_ADD);

                        ngx_dynamic_upstream_op(ngx_cycle->log, &op,
                            hscf->uscf);

                        if (ngx_strcmp(noaddr.data, peer->name.data) != 0)
                            goto again;
                    } else
                        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                                      "http_upsync upstream: [%V] %s",
                                      &op.upstream, op.err);
                }
            }
        }
    }

    ngx_rwlock_unlock(&primary->rwlock);
}


static void
ngx_http_upsync_sync_upstream_ready(ngx_http_upsync_upstream_srv_conf_t *hscf,
    ngx_array_t *names)
{
    ngx_uint_t                     j;
    ngx_dynamic_upstream_op_t      op;
    ngx_str_t                     *elts;

    elts = names->elts;

    for (j = 0; j < names->nelts; j++) {

        if (!ngx_http_upsync_exists(hscf->uscf->peer.data, elts + j)) {

            ngx_http_upsync_op_defaults(&op, &hscf->uscf->host, elts + j,
                NULL, NGX_DYNAMIC_UPSTEAM_OP_ADD);

            if (ngx_dynamic_upstream_op(ngx_cycle->log, &op, hscf->uscf)
                    == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "http_upsync upstream: [%V] %s", &op.upstream,
                              op.err);
            }
        }
    }

    ngx_http_upsync_remove_obsoleted(hscf, names);

    if (hscf->file.data)
        ngx_http_upsync_upstream_save(hscf);
}


typedef struct {
    ngx_pool_t                           *pool;
    ngx_http_upsync_upstream_srv_conf_t  *hscf;
} ngx_http_upsync_sync_request_ctx_t;


static void
ngx_http_upsync_sync_upstream_handler(ngx_int_t rc,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body, void *data)
{
    ngx_http_upsync_sync_request_ctx_t  *ctx = data;
    ngx_array_t                         *names;
    u_char                              *s1, *s2;
    ngx_str_t                           *name;
    ngx_uint_t                           hash = 0;

    if (rc == NGX_ERROR) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                     "http_upsync upstream: [%V], failed to upsync",
                     &ctx->hscf->uscf->host);
        goto end;
    } else if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                     "http_upsync upstream: [%V], upsync timeout",
                     &ctx->hscf->uscf->host);
        goto end;
    } else if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {

        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                     "http_upsync upstream: [%V], upsync status=%d",
                     &ctx->hscf->uscf->host, rc);
        goto end;
    }

    names = ngx_array_create(ctx->pool, 20, sizeof(ngx_str_t));
    if (names == NULL)
        goto nomem;

    for (s1 = s2 = body->data; s2 < body->data + body->len; s2++) {
        if (*s2 == LF || s2 == body->data + body->len - 1) {
            name = ngx_array_push(names);
            if (name == NULL)
                goto nomem;
            name->data = s1;
            name->len = s2 - s1;
            hash += ngx_crc32_short(name->data, name->len);
            if (*s2 == LF)
                *s2++ = 0;
            while (s2 < body->data + body->len && isspace(*s2))
                s2++;
            s1 = s2;
        }
    }

    if (hash != ctx->hscf->hash) {

        if (names->nelts != 0 || body->len == 0)
            ngx_http_upsync_sync_upstream_ready(ctx->hscf, names);
        else {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                         "http_upsync upstream: [%V], failed to parse (empty?)",
                         &ctx->hscf->uscf->host);
        }

        ctx->hscf->hash = hash;
    }

end:

    ngx_destroy_pool(ctx->pool);

    ctx->hscf->last = ngx_current_msec;
    ctx->hscf->busy = 0;

    return;

nomem:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no memory");
    ngx_destroy_pool(ctx->pool);
}


static ngx_int_t
ngx_http_upsync_sync_upstream(ngx_http_upsync_upstream_srv_conf_t *hscf)
{
    ngx_http_upsync_sync_request_ctx_t  *ctx;
    ngx_pool_t                          *pool;
    static ngx_str_t GET = ngx_string("GET");

    if (hscf->busy)
        return NGX_OK;

    if (hscf->last + hscf->interval > ngx_current_msec)
        return NGX_OK;

    hscf->busy = 1;

    pool = ngx_create_pool(1024, ngx_cycle->log);
    if (pool == NULL)
        goto nomem;

    ctx = ngx_palloc(pool, sizeof(ngx_http_upsync_sync_request_ctx_t));
    if (ctx == NULL)
        goto nomem;

    ctx->pool = pool;
    ctx->hscf = hscf;
    
    ngx_http_send_request(pool, GET, &hscf->url, NULL, 0,
        hscf->headers->elts, hscf->headers->nelts, NULL,
        hscf->timeout, ngx_http_upsync_sync_upstream_handler, ctx);

    return NGX_OK;

nomem:

    if (pool != NULL)
        ngx_destroy_pool(pool);

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no memory");

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_upsync_sync_upstreams(ngx_cycle_t *cycle)
{
    ngx_http_upstream_main_conf_t         *umcf;
    ngx_http_upstream_srv_conf_t         **uscf;
    ngx_http_upsync_upstream_srv_conf_t   *hscf;
    ngx_core_conf_t                       *ccf;
    ngx_uint_t                             j;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
        ngx_http_upstream_module);
    uscf = umcf->upstreams.elts;

    for (j = 0; j < umcf->upstreams.nelts; j++) {
        hscf = ngx_http_conf_upstream_srv_conf(uscf[j],
            ngx_http_upsync_upstream_module);

        if (hscf->uscf == NULL)
            continue;

        if (j % ccf->worker_processes == ngx_worker)
            ngx_http_upsync_sync_upstream(hscf);
    }

    return NGX_OK;
}