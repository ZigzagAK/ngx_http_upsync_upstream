/*
 * Copyright (C) 2018 Aleksei Konovkin (alkon2000@mail.ru)
 */

#ifndef _ngx_http_send_request_h_
#define _ngx_http_send_request_h_


#include <ngx_core.h>
#include <ngx_config.h>


typedef void (*ngx_http_send_request_pt)(ngx_int_t rc,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body, void *data);


ngx_int_t
ngx_http_send_request(ngx_pool_t *pool, ngx_str_t method, ngx_url_t *url,
    ngx_keyval_t *args, ngx_uint_t nargs,
    ngx_keyval_t *headers, ngx_uint_t nheaders,
    ngx_str_t *body,
    ngx_msec_t timeout,
    ngx_http_send_request_pt handler,
    void *data);


#endif