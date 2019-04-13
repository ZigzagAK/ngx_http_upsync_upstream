use lib 'lib';
use Test::Nginx::Socket;

no_shuffle();

repeat_each(2);
plan tests => repeat_each() * (2 + blocks() * 2);

run_tests();

__DATA__

=== TEST 1: simple
--- config
    location @dynamic {
        dynamic_upstream;
    }
    location = /test {
        echo_sleep 1;
        echo_exec @dynamic;
    }
--- http_config
    server {
      listen localhost:2345;
      location = /registry/u1 {
        echo "127.0.0.1:6001";
        echo "127.0.0.1:6002";
        echo "127.0.0.1:6003";
      }
    }
    upstream backend {
        zone shm_backends 128k;

        upsync localhost:2345/registry/u1;

        upsync_interval 1s;
        upsync_timeout 1s;

        upsync_file backend.peers;
    }
--- timeout: 2
--- request
    GET /test?upstream=backend
--- response_body_like
^server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;$


=== TEST 2: simple resolve
--- config
    location @dynamic {
        dynamic_upstream;
    }
    location = /test {
        echo_sleep 2;
        echo_exec @dynamic;
    }
--- http_config
    server {
      listen localhost:2345;
      location = /registry/u1 {
        echo "localhost:6001";
        echo "localhost:6002";
        echo "localhost:6003";
      }
    }
    upstream backend {
        zone shm_backends 128k;

        upsync localhost:2345/registry/u1;

        upsync_interval 1s;
        upsync_timeout 1s;

        dns_update 1s;

        upsync_file backend.peers;
    }
--- timeout: 3
--- request
    GET /test?upstream=backend
--- response_body_like
^server localhost:6001 addr=127.0.0.1:6001;
server localhost:6002 addr=127.0.0.1:6002;
server localhost:6003 addr=127.0.0.1:6003;$


=== TEST 3: with defaults
--- config
    location @dynamic {
        dynamic_upstream;
    }
    location = /test {
        echo_sleep 1;
        echo_exec @dynamic;
    }
--- http_config
    server {
      listen localhost:2345;
      location = /registry/u1 {
        echo "127.0.0.1:6001";
        echo "127.0.0.1:6002";
        echo "127.0.0.1:6003";
      }
    }
    upstream backend {
        zone shm_backends 128k;

        upsync localhost:2345/registry/u1;
        upsync_defaults max_conns=10 max_fails=10 fail_timeout=30s;

        upsync_interval 1s;
        upsync_timeout 1s;

        upsync_file backend.peers;
    }
--- timeout: 2
--- request
    GET /test?upstream=backend&verbose=
--- response_body_like
^server 127.0.0.1:6001 addr=127.0.0.1:6001 weight=1 max_fails=10 fail_timeout=30000 max_conns=10 conns=0;
server 127.0.0.1:6002 addr=127.0.0.1:6002 weight=1 max_fails=10 fail_timeout=30000 max_conns=10 conns=0;
server 127.0.0.1:6003 addr=127.0.0.1:6003 weight=1 max_fails=10 fail_timeout=30000 max_conns=10 conns=0;$


=== TEST 4: simple 2 upstreams
--- config
    location @dynamic {
        dynamic_upstream;
    }
    location = /test {
        echo_sleep 1;
        echo_exec @dynamic;
    }
--- http_config
    server {
      listen localhost:2345;
      location = /registry/u1 {
        echo "127.0.0.5:6001";
        echo "127.0.0.5:6002";
        echo "127.0.0.5:6003";
      }
      location = /registry/u2 {
        echo "localhost:6001";
        echo "localhost:6002";
        echo "localhost:6003";
      }
    }
    upstream backend1 {
        zone shm_backends1 128k;

        upsync localhost:2345/registry/u1;

        upsync_interval 1s;
        upsync_timeout 1s;

        upsync_file backend1.peers;
    }
    upstream backend2 {
        zone shm_backends2 128k;

        upsync localhost:2345/registry/u2;

        upsync_interval 1s;
        upsync_timeout 1s;

        dns_update 1s;

        upsync_file backend2.peers;
    }
--- timeout: 2
--- request eval
["GET /test?upstream=backend1", "GET /test?upstream=backend2"]
--- response_body eval
["server 127.0.0.5:6001 addr=127.0.0.5:6001;
server 127.0.0.5:6002 addr=127.0.0.5:6002;
server 127.0.0.5:6003 addr=127.0.0.5:6003;
","server localhost:6001 addr=127.0.0.1:6001;
server localhost:6002 addr=127.0.0.1:6002;
server localhost:6003 addr=127.0.0.1:6003;
"]


=== TEST 5: with params
--- config
    location @dynamic {
        dynamic_upstream;
    }
    location = /test {
        echo_sleep 1;
        echo_exec @dynamic;
    }
--- http_config
    server {
      listen localhost:2345;
      location = /registry/u1 {
        echo "127.0.0.1:6001";
        echo "127.0.0.1:6002 weight=2 max_conns=20 max_fails=2 fail_timeout=5s";
        echo "127.0.0.1:6003 max_conns=50 max_fails=5 fail_timeout=10s backup";
      }
    }
    upstream backend {
        zone shm_backends 128k;

        upsync localhost:2345/registry/u1;
        upsync_defaults max_conns=10 max_fails=10 fail_timeout=30s;

        upsync_interval 1s;
        upsync_timeout 1s;

        upsync_file backend.peers;
    }
--- timeout: 2
--- request
    GET /test?upstream=backend&verbose=
--- response_body_like
^server 127.0.0.1:6001 addr=127.0.0.1:6001 weight=1 max_fails=10 fail_timeout=30000 max_conns=10 conns=0;
server 127.0.0.1:6002 addr=127.0.0.1:6002 weight=2 max_fails=2 fail_timeout=5000 max_conns=20 conns=0;
server 127.0.0.1:6003 addr=127.0.0.1:6003 weight=1 max_fails=5 fail_timeout=10000 max_conns=50 conns=0 backup;$

