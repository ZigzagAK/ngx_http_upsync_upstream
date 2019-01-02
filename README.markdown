Name
====

ngx_http_upsync_upstream - Upstream synced by http request.

# Quick Start

## Nginx config

```nginx
http {
  healthcheck_buffer_size 128k;

  upstream app1 {
    zone shm_app1 128k;

    upsync localhost:8888/registry/nodes?service=app1;
    upsync_header Accept text/plain;
    upsync_interval 10s;
    upsync_timeout 10s;
    upsync_file conf/app1.peers;

    dns_update 60s;
    dns_add_down on;

    check passive type=http rise=2 fall=2 timeout=5000 interval=10;
    check_request_uri GET /health;
    check_response_codes 200;
    check_response_body alive;

    include app1.peers;
  }

  upstream app2 {
    zone shm_app2 128k;

    upsync localhost:8888/registry/nodes?service=app2;
    # Admin:1111
    upsync_header Authorization "Bearer QWRtaW46MTExMQ==";
    upsync_header Accept text/plain;
    upsync_interval 10s;
    upsync_timeout 10s;
    upsync_file conf/app2.peers;

    dns_update 60s;
    dns_add_down on;

    check passive type=http rise=2 fall=2 timeout=5000 interval=10;
    check_request_uri GET /health;
    check_response_codes 200;
    check_response_body alive;

    include app2.peers;
  }

  server {
    listen 6000;

    location /dynamic {
      dynamic_upstream;
    }
  }

  server {
    # app1
    listen 8001;
    listen 8002;

    #app2
    listen 9001;
    listen 9002;

    location = /health {
      return 200 'alive';
    }

    location / {
      access_log off;
      return 200 'hello';
    }
  }

  server {
    listen 10000;

    access_log off;

    location /app1 {
      proxy_pass http://app1;
    }

    location /app2 {
      proxy_pass http://app2;
    }
  }

  server {
    listen 8888;

    location = /registry/nodes {
      if ($arg_service = app1) {
        echo localhost:8001;
        echo localhost:8002;
      }
      if ($arg_service = app2) {
        echo localhost:9001;
        echo localhost:9002;
      }
    }

    location /dynamic {
      dynamic_upstream;
    }

    location /healthcheck/get {
      healthcheck_get;
    }

    location /healthcheck/status {
      healthcheck_status;
    }
  }
}
````
