# Plex Nginx Reverse Proxy
 
This configuration will allow you to serve Plex via Nginx behind CloudFlare

 * Originally based on https://github.com/toomuchio/plex-nginx-reverseproxy
 * Build script based on https://github.com/MatthewVance/nginx-build

## Features

 * nginx 1.18.0
 * BoringSSL - https://github.com/google/boringssl
 * QUIC transport protocol and HTTP/3 - https://github.com/cloudflare/quiche
 * Add HTTP2 HPACK Encoding Support - https://github.com/kn007/patch/blob/master/nginx_with_quic.patch
 * Add Dynamic TLS Record support - https://github.com/kn007/patch/blob/master/nginx_with_quic.patch
 * Hide Server Signature - https://github.com/torden/ngx_hidden_signature_patch 
 * brotli compression support - https://github.com/google/ngx_brotli
 * More Headers - https://github.com/openresty/headers-more-nginx-module
 * Cloudflare ZLIB - https://github.com/cloudflare/zlib
 * Prevents public access to PMS built-in web interface
 * tmpfs cache (1GB) for Plex images
 
## Minimal Requirements
 
Plex:
* Remote Access - Disable
* Network - Custom server access URLs = `https://<your-domain>:443,http://<your-domain>:80`
* Network - Secure connections = Preferred
 
## Requirements

System: 
* Debian Buster x64 (10.8)
* tmpfs for cache - add "tmpfs /var/cache/nginx/ram_cache/ tmpfs defaults,size=1024M 0 0" to fstab

Build Script:
* GCC 10.1 - https://solarianprogrammer.com/2016/10/07/building-gcc-ubuntu-linux/
* golang - https://golang.org/doc/install
* Rust 1.47 or later - https://rustup.rs

Cloudflare:
* SSL: https://support.cloudflare.com/hc/en-us/categories/200276247-SSL-TLS
* Disable ipv6 connectivity

iptables:
* Deny port 32400 externally (Plex still pings over 32400, some clients may use 32400 by mistake despite 443 and 80 being set)
* Note adding `allowLocalhostOnly="1"` to your Preferences.xml, will make Plex only listen on the localhost, achieving the same thing as using a firewall
* Only allow CloudFlare IPs via iptables using ipset

```
ipset create cf hash:net
for x in $(curl https://www.cloudflare.com/ips-v4); do ipset add cf $x; done
iptables -A INPUT -p tcp -m tcp --dport 32400 -j DROP
iptables -A INPUT -m set --match-set cf src -p tcp -m multiport --dports http,https -j ACCEPT
iptables -A INPUT -m set --match-set cf src -p udp -m multiport --dports https -j ACCEPT
