#include "ngx_http_send_request.h"
#include <assert.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_send_request_pt  handler;
    void                     *data;

    ngx_url_t                *url;
    ngx_buf_t                *request;
    ngx_msec_t                timeout;

    ngx_pool_t               *pool;
    ngx_http_status_t         status;
    ngx_array_t              *headers;
    ngx_chain_t              *body;
    ngx_chain_t              *chains;

    ngx_flag_t                headers_readed;
    ngx_int_t                 remains;
    ngx_http_chunked_t       *chunked;
    ngx_buf_t                *last;
    ngx_http_request_t        r;
    ngx_str_t                 traceid;
} ngx_http_send_request_ctx_t;


#define ERR_FMT "[%V] http_request:%s() %s, host=%V:%d, URL: %V"

#define log_error_details(log_level, ctx, fun, err, fmt, ...)       \
    ngx_log_error(log_level, ngx_cycle->log,                        \
        log_level < NGX_LOG_NOTICE ? ngx_socket_errno : 0,          \
        ERR_FMT ", " fmt,                                           \
        &ctx->traceid, fun, err ? err : "error",                    \
        &ctx->url->host, ctx->url->port, &ctx->url->uri,            \
        __VA_ARGS__)


#define log_error(log_level, ctx, fun, err)                         \
    ngx_log_error(log_level, ngx_cycle->log,                        \
        log_level < NGX_LOG_NOTICE ? ngx_socket_errno : 0,          \
        ERR_FMT,                                                    \
        &ctx->traceid, fun, err ? err : "error",                    \
        &ctx->url->host, ctx->url->port, &ctx->url->uri)


static ngx_int_t
test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                           (char *) "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
            err = ngx_socket_errno;
        else
            ngx_socket_errno = err;

        if (err)
            return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
handle_event(ngx_event_t *ev)
{
    ngx_connection_t  *c = (ngx_connection_t *) ev->data;

    if (ev->write) {

        if (ngx_handle_write_event(c->write, 0) == NGX_OK)
            return NGX_OK;

        test_connect(c);
        return NGX_ERROR;
    }

    if (ngx_handle_read_event(c->read, 0) == NGX_OK)
        return NGX_OK;

    test_connect(c);
    return NGX_ERROR;
}


static ngx_int_t
handle_io_event(ngx_event_t *ev)
{
    if (ev->ready)
        return handle_event(ev);

    return NGX_OK;
}


static void
handle_dummy(ngx_event_t *ev)
{
    ngx_connection_t             *c = ev->data;
    ngx_http_send_request_ctx_t  *ctx = c->data;

    if (handle_io_event(ev) == NGX_OK)
        return;

    log_error(NGX_LOG_ERR, ctx, "dummy", NULL);

    ngx_close_connection(c);

    ctx->handler(NGX_ERROR, NULL, 0, NULL, ctx->data);
}


static void handle_read(ngx_event_t *ev);


static void
handle_write(ngx_event_t *ev)
{
    ngx_connection_t             *c = ev->data;
    ngx_http_send_request_ctx_t  *ctx = c->data;
    ssize_t                       size;

    if (ev->timedout) {

        log_error(NGX_LOG_ERR, ctx, "write", "timeout");
        ngx_close_connection(c);

        return ctx->handler(NGX_DECLINED, NULL, 0, NULL, ctx->data);
    }

    size = c->send(c, ctx->request->pos,
        ctx->request->last - ctx->request->pos);

    if (size == NGX_ERROR) {

        log_error(NGX_LOG_ERR, ctx, "write", NULL);
        ngx_close_connection(c);

        return ctx->handler(NGX_ERROR, NULL, 0, NULL, ctx->data);
    }

    if (size == NGX_AGAIN)
        return;

    ctx->request->pos += size;

    if (ctx->request->pos < ctx->request->last)
        return;

    // request has been sent

    if (handle_io_event(ev) == NGX_ERROR) {

        log_error(NGX_LOG_ERR, ctx, "write", NULL);
        ngx_close_connection(c);

        return ctx->handler(NGX_ERROR, NULL, 0, NULL, ctx->data);
    }

    ngx_del_timer(c->write);

    c->read->handler = handle_read;
    c->write->handler = handle_dummy;

    ngx_add_timer(c->read, ctx->timeout);
    handle_read(c->read);
}


static void
process_content_length(ngx_http_send_request_ctx_t *ctx, ngx_keyval_t *h)
{
    static ngx_str_t  c_length = ngx_string("content-length");

    if (ctx->remains != -1)
        return;

    if (h->key.len != c_length.len)
        return;

    if (ngx_strncasecmp(h->key.data, c_length.data, c_length.len) == 0)
        ctx->remains = ngx_atoi(h->value.data, h->value.len);
}


static void
process_transfer_encoding(ngx_http_send_request_ctx_t *ctx, ngx_keyval_t *h)
{
    static ngx_str_t  t_encoding = ngx_string("transfer-encoding");
    static ngx_str_t  chunked    = ngx_string("chunked");

    if (ctx->remains != -1 || ctx->chunked != NULL)
        return;

    if (h->key.len != t_encoding.len || h->value.len != chunked.len)
        return;

    if (ngx_strncasecmp(h->key.data, t_encoding.data, t_encoding.len) != 0
        || ngx_strncasecmp(h->value.data, chunked.data, chunked.len) != 0)
        return;

    ctx->chunked = ngx_pcalloc(ctx->pool, sizeof(ngx_http_chunked_t));
}


static void
ngx_set_string(ngx_str_t *s, u_char *b, u_char *e)
{
    s->len = e - b;
    s->data = b;
    s->data[s->len] = 0;
}


static ngx_int_t
parse_header(ngx_http_send_request_ctx_t *ctx)
{
    ngx_http_request_t  *r = &ctx->r;
    ngx_keyval_t        *h;

    switch (ngx_http_parse_header_line(r, ctx->last, 1)) {
        case NGX_OK:
            break;

        case NGX_AGAIN:
            return NGX_AGAIN;

        case NGX_HTTP_PARSE_HEADER_DONE:
            return NGX_HTTP_PARSE_HEADER_DONE;

        case NGX_HTTP_PARSE_INVALID_HEADER:
            return NGX_DECLINED;

        case NGX_ERROR:
        default:
            return NGX_ERROR;
    }

    if (r->header_name_end == r->header_name_start)
        return NGX_DECLINED;

    h = ngx_array_push(ctx->headers);
    if (h == NULL)
        return NGX_ERROR;

    ngx_set_string(&h->key, r->header_name_start, r->header_name_end);
    ngx_set_string(&h->value, r->header_start, r->header_end);

    log_error_details(NGX_LOG_DEBUG, ctx, "recv", "header", "%V: %V",
        &h->key, &h->value);

    process_content_length(ctx, h);
    process_transfer_encoding(ctx, h);

    return NGX_OK;
}


static ngx_int_t
parse_headers(ngx_http_send_request_ctx_t *ctx)
{
    for (;;) {

        switch (parse_header(ctx)) {

            case NGX_OK:
            case NGX_DECLINED:
                continue;

            case NGX_AGAIN:
                return NGX_AGAIN;

            case NGX_HTTP_PARSE_HEADER_DONE:
                return NGX_HTTP_PARSE_HEADER_DONE;
        }

        break;
    }

    return NGX_ERROR;
}


static ngx_int_t
parse_body(ngx_http_send_request_ctx_t *ctx)
{
    if (ctx->headers_readed && ctx->body == NULL) {

        ctx->last->start = ctx->last->pos;
        ctx->body = ctx->chains;
    }

    if (ctx->chunked != NULL) {

        log_error(NGX_LOG_ERR, ctx, "write", "chunked unsupported");
        return NGX_ERROR;
    }

    if (ctx->remains == -1)
        // receiving data until to close connection for HTTP/1.0
        return NGX_AGAIN;

    ctx->remains -= ctx->last->last - ctx->last->pos;

    if (ctx->remains < 0) {

        // fix buffer to content-length header
        ctx->last->last += ctx->remains;
        ctx->remains = 0;
    }

    if (ctx->remains == 0)
        return NGX_OK;

    return NGX_AGAIN;
}


static ngx_int_t
receive_data(ngx_connection_t *c)
{
    ngx_http_send_request_ctx_t  *ctx = c->data;
    ngx_chain_t                  *ch;
    ssize_t                       size;
    ngx_str_t                     chunk;

    if (ctx->last->end == ctx->last->last) {

        ch = ngx_pcalloc(ctx->pool, sizeof(ngx_chain_t));
        if (ch == NULL)
            return NGX_ERROR;

        ch->buf = ngx_create_temp_buf(ctx->pool, ngx_pagesize);
        if (ch->buf == NULL)
            return NGX_ERROR;

        ctx->chains->next = ch;
        ctx->chains = ch;
        ctx->last = ch->buf;
    }

    if (ctx->chunked != NULL || ctx->remains == -1)
        size = c->recv(c, ctx->last->last, ctx->last->end - ctx->last->last);
    else
        size = c->recv(c, ctx->last->last,
            ngx_min(ctx->remains, ctx->last->end - ctx->last->last));

    log_error_details(NGX_LOG_DEBUG, ctx, "recv", "data", "rc=%l, eof=%ud",
        size, c->read->pending_eof);

    if (size > 0) {
        chunk.data = ctx->last->last;
        chunk.len = size;
        log_error_details(NGX_LOG_DEBUG, ctx, "recv", "data", "chunk:\n%V",
            &chunk);
    }

    if (size == NGX_ERROR)
        return c->read->pending_eof ? NGX_OK : NGX_ERROR;

    if (size == NGX_AGAIN)
        return NGX_AGAIN;

    ctx->last->last += size;

    return c->read->pending_eof ? NGX_OK : NGX_DONE;
}


static ngx_int_t
receive_body(ngx_connection_t *c)
{
    ngx_http_send_request_ctx_t  *ctx = c->data;

    for (;;) {

        switch (parse_body(ctx)) {

            case NGX_OK:
                return NGX_OK;

            case NGX_AGAIN:
                break;
        }

        switch (receive_data(c)) {

            case NGX_OK:
                return NGX_OK;

            case NGX_DONE:
                continue;

            case NGX_AGAIN:
                return NGX_AGAIN;
        }

        break;
    }

    return NGX_ERROR;
}


static ngx_int_t
receive_response(ngx_connection_t *c)
{
    ngx_http_send_request_ctx_t  *ctx = c->data;

    log_error(NGX_LOG_DEBUG, ctx, "recv",
         ctx->headers_readed ? "continue" : "start");

    if (ctx->headers_readed)
        return receive_body(c);

    for (;;) {

        // receiving status line

        switch (ngx_http_parse_status_line(&ctx->r, ctx->last, &ctx->status)) {

            case NGX_OK:
                log_error_details(NGX_LOG_DEBUG, ctx, "recv", "status line",
                    "code=%ud", ctx->status.code);
                break;

            case NGX_AGAIN:
                goto receive;

            case NGX_ERROR:
            default:
                return NGX_ERROR;
        }

        // receiving headers

        switch (parse_headers(ctx)) {

            case NGX_HTTP_PARSE_HEADER_DONE:
                ctx->headers_readed = 1;
                if (ctx->status.code == NGX_HTTP_NO_CONTENT)
                    return NGX_OK;
                return receive_body(c);

            case NGX_AGAIN:
                goto receive;

            case NGX_ERROR:
            default:
                return NGX_ERROR;
        }

receive:

        switch (receive_data(c)) {
            case NGX_OK:
            case NGX_DONE:
                continue;

            case NGX_AGAIN:
                return NGX_AGAIN;

            case NGX_ERROR:
            default:
                return NGX_ERROR;
        }
    }

    return NGX_ERROR;
}


static void
handle_read(ngx_event_t *ev)
{
    ngx_connection_t             *c = ev->data;
    ngx_http_send_request_ctx_t  *ctx = c->data;
    ngx_str_t                    *body;
    size_t                        size;
    ngx_chain_t                  *tmp;

    if (ev->timedout) {

        log_error(NGX_LOG_ERR, ctx, "read", "timeout");
        ngx_close_connection(c);

        return ctx->handler(NGX_DECLINED, NULL, 0, NULL, ctx->data);
    }

    switch (receive_response(c)) {

        case NGX_OK:

            break;

        case NGX_AGAIN:

            if (handle_io_event(ev) == NGX_OK)
                return;

        case NGX_ERROR:
        default:

            log_error(NGX_LOG_ERR, ctx, "read", NULL);
            ngx_close_connection(c);

            return ctx->handler(NGX_ERROR, NULL, 0, NULL, ctx->data);
    }

    ngx_close_connection(c);

    body = ngx_pcalloc(ctx->pool, sizeof(ngx_str_t));
    if (body == NULL)
        goto nomem;

    if (ctx->body != NULL) {

        if (ctx->body->next == NULL) {

            body->data = ctx->body->buf->start;
            body->len = ctx->body->buf->last - ctx->body->buf->start;

        } else {

            size = 0;
            for (tmp = ctx->body; tmp; tmp = tmp->next)
                size += tmp->buf->last - tmp->buf->start;

            body->data = ngx_palloc(ctx->pool, size);
            if (body->data == NULL)
                goto nomem;

            for (tmp = ctx->body; tmp; tmp = tmp->next) {
                ngx_memcpy(body->data + body->len, tmp->buf->start,
                    tmp->buf->last - tmp->buf->start);
                body->len += tmp->buf->last - tmp->buf->start;
            }

            assert(size == body->len);
        }
    } else {

        ngx_str_set(body, "");
    }

    log_error_details(NGX_LOG_DEBUG, ctx, "request", "completed",
        "code=%ud", ctx->status.code);

    return ctx->handler(ctx->status.code,
        ctx->headers->elts, ctx->headers->nelts, body, ctx->data);

nomem:

    log_error(NGX_LOG_ERR, ctx, "read", "no memory");

    ctx->handler(NGX_ERROR, NULL, 0, NULL, ctx->data);
}


static void
handle_connect(ngx_event_t *ev)
{
    ngx_connection_t             *c = ev->data;
    ngx_http_send_request_ctx_t  *ctx = c->data;

    if (ev->timedout) {

        log_error(NGX_LOG_ERR, ctx, "connect", "timeout");
        ngx_close_connection(c);

        return ctx->handler(NGX_DECLINED, NULL, 0, NULL, ctx->data);
    }

    if (handle_io_event(ev) == NGX_ERROR) {

        log_error(NGX_LOG_ERR, ctx, "connect", NULL);
        ngx_close_connection(c);

        return ctx->handler(NGX_ERROR, NULL, 0, NULL, ctx->data);
    }

    c->read->handler = handle_dummy;
    c->write->handler = handle_write;

    ngx_add_timer(c->write, ctx->timeout);

    handle_write(c->write);
}


static ngx_buf_t *
build_http_request(ngx_pool_t *pool, ngx_str_t method, ngx_url_t *url,
    ngx_keyval_t *args, ngx_uint_t nargs,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body);


ngx_int_t
ngx_http_send_request(ngx_pool_t *pool, ngx_str_t method, ngx_url_t *url,
    ngx_keyval_t *args, ngx_uint_t nargs,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body,
    ngx_msec_t timeout,
    ngx_http_send_request_pt handler,
    void *data)
{
    ngx_buf_t                    *request;
    ngx_http_send_request_ctx_t  *ctx;
    ngx_peer_connection_t        *pc;
    ngx_connection_t             *c;
    ngx_int_t                     rc;
    ngx_uint_t                    j;

    static char  alphabet[] = "1234567890abcdef";

    request = build_http_request(pool, method, url,
        args, nargs, headers, nheaders, body);

    if (request == NULL)
        return NGX_ERROR;

    ctx = ngx_pcalloc(pool, sizeof(ngx_http_send_request_ctx_t));
    if (ctx == NULL)
        return NGX_ERROR;

    ctx->traceid.data = ngx_pcalloc(pool, 17);
    if (ctx->traceid.data == NULL)
        return NGX_ERROR;

    for (j = 0; j < 16; j++)
        ctx->traceid.data[j] = alphabet[ngx_random() % (sizeof(alphabet) - 1)];
    ctx->traceid.len = 16;

    ctx->handler = handler;
    ctx->data    = data;
    ctx->request = request;
    ctx->timeout = timeout;
    ctx->pool    = pool;
    ctx->url     = url;
    ctx->remains = -1;

    ctx->headers = ngx_array_create(pool, 20, sizeof(ngx_keyval_t));
    if (ctx->headers == NULL)
        return NGX_ERROR;

    ctx->chains = ngx_pcalloc(pool, sizeof(ngx_chain_t));
    if (ctx->chains == NULL)
        return NGX_ERROR;

    ctx->chains->buf = ngx_create_temp_buf(pool, ngx_pagesize * 8);
    if (ctx->chains->buf== NULL)
        return NGX_ERROR;
    ctx->last = ctx->chains->buf;

    pc = ngx_pcalloc(pool, sizeof(ngx_peer_connection_t));
    if (pc == NULL)
        return NGX_ERROR;

    pc->sockaddr  = &url->sockaddr.sockaddr;
    pc->socklen   = url->socklen;
    pc->name      = &url->host;
    pc->get       = ngx_event_get_peer;
    pc->log       = ngx_cycle->log;
    pc->log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(pc);

    if (rc == NGX_ERROR || rc == NGX_DECLINED || rc == NGX_BUSY) {

        ctx->handler(NGX_ERROR, NULL, 0, NULL, ctx->data);
        return NGX_ERROR;
    }

    c = pc->connection;

    c->data       = ctx;
    c->pool       = pool;
    c->log        = ngx_cycle->log;
    c->read->log  = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->sendfile   = 0;

    log_error(NGX_LOG_DEBUG, ctx, "request", "begin");

    if (rc != NGX_AGAIN) {

        c->write->handler = handle_write;
        c->read->handler = handle_dummy;

        ngx_add_timer(c->write, timeout);
        handle_write(c->write);

        return NGX_DONE;
    }

    c->write->handler = handle_connect;
    c->read->handler = handle_connect;

    ngx_add_timer(c->write, timeout);

    return NGX_DONE;
}


static ngx_buf_t *
build_http_request(ngx_pool_t *pool, ngx_str_t method, ngx_url_t *url,
    ngx_keyval_t *args, ngx_uint_t nargs,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body)
{
    ngx_buf_t    *buf;
    ngx_uint_t    i;
    size_t        size = 64 + url->uri.len;

    for (i = 0; i < nargs; i++)
        size += 2 + args[i].key.len + args[i].value.len;
    for (i = 0; i < nheaders; i++)
        size += 4 + headers[i].key.len + headers[i].value.len;

    if (body != NULL)
        size += body->len;

    buf = ngx_create_temp_buf(pool,
        ngx_align(size + ngx_pagesize, ngx_pagesize));
    if (buf == NULL)
        return NULL;

    buf->last = ngx_snprintf(buf->last, buf->end - buf->last, "%V %V",
        &method, &url->uri);

    if (nargs != 0) {
        buf->last = ngx_snprintf(buf->last, buf->end - buf->last, "?");
        for (i = 0; i < nargs; i++) {
            buf->last = ngx_snprintf(buf->last, buf->end - buf->last,
                "%V=%V", &args[i].key, &args[i].value);
            if (i != nargs - 1)
                buf->last = ngx_snprintf(buf->last, buf->end - buf->last, "&");
        }
    }

    buf->last = ngx_snprintf(buf->last, buf->end - buf->last, " HTTP/1.0"CRLF);

    buf->last = ngx_snprintf(buf->last, buf->end - buf->last,
        "Host: %V:%d"CRLF, &url->host, url->port);

    buf->last = ngx_snprintf(buf->last, buf->end - buf->last,
        "User-Agent: nginx/"NGINX_VERSION CRLF
        "Connection: close"CRLF);

    for (i = 0; i < nheaders; i++)
        buf->last = ngx_snprintf(buf->last, buf->end - buf->last,
            "%V: %V"CRLF,
            &headers[i].key,
            &headers[i].value);

    if (body != NULL && body->len != 0)
        buf->last = ngx_snprintf(buf->last, buf->end - buf->last,
            "Content-Length: %d"CRLF CRLF"%V",
            body->len, body);
    else
        buf->last = ngx_snprintf(buf->last, buf->end - buf->last, CRLF);

    return buf;
}
