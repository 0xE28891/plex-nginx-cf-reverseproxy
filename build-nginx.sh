#!/usr/bin/env bash
# Run as root or with sudo

export PATH=$PATH:/usr/local/go/bin
source $HOME/.cargo/env

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or with sudo."
  exit 1
fi

# Make script exit if a simple command fails and
# Make script print commands being executed
set -e -x

# Set names of latest versions of each package
version_pcre=pcre-8.44
version_nginx=nginx-1.18.0
version_libatomic=7.6.10
version_headers=0.33

# Set checksums of latest versions
sha256_pcre=aecafd4af3bd0f3935721af77b889d9024b2e01d96b58471bd91a3063fb47728
sha256_nginx=4c373e7ab5bf91d34a4f11a0c9496561061ba5eee6020db272a17a7228d35f99
sha256_libatomic=e6b0909cf4e63cec693fe6c48191ce864c32c5113e16c3f517aa2a244b46992f
sha256_headers=a3dcbab117a9c103bc1ea5200fc00a7b7d2af97ff7fd525f16f8ac2632e30fbf

# Set URLs to the source directories
source_pcre=https://ftp.pcre.org/pub/pcre/
source_zlib=https://github.com/cloudflare/zlib
source_nginx=https://nginx.org/download/
source_libatomic=https://github.com/ivmai/libatomic_ops/archive/v
source_brotli=https://github.com/google/ngx_brotli
source_headers=https://github.com/openresty/headers-more-nginx-module/archive/v
source_quiche=https://github.com/cloudflare/quiche

# Set where OpenSSL and NGINX will be built
path=$(pwd)
bpath=$path/build
time=$(date +%m%d%Y-%H%M%S-%Z)

# Clean screen before launching
clear

# Clean out any files from previous runs of this script
rm -rf \
  "$bpath"
mkdir "$bpath"
rm -rf \
  "$path/package"
mkdir "$path/package"

# Move tmp within build directory
mkdir "$bpath/tmp"
export TMPDIR="$bpath/tmp"

# Add backports repo
echo "deb http://ftp.debian.org/debian buster-backports main" | tee /etc/apt/sources.list.d/backports.list

# Ensure the required software to compile NGINX is installed
apt-get update && apt-get -y install \
  binutils \
  build-essential \
  checkinstall \
  cmake \
  autoconf \
  automake \
  libtool \
  git \
  curl \
  wget

# Download the source files and verify their checksums
curl -L "${source_pcre}${version_pcre}.tar.gz" -o "${bpath}/pcre.tar.gz" && \
  echo "${sha256_pcre} ${bpath}/pcre.tar.gz" | sha256sum -c -
curl -L "${source_nginx}${version_nginx}.tar.gz" -o "${bpath}/nginx.tar.gz" && \
 echo "${sha256_nginx} ${bpath}/nginx.tar.gz" | sha256sum -c -
curl -L "${source_libatomic}${version_libatomic}.tar.gz" -o "${bpath}/libatomic.tar.gz" && \
  echo "${sha256_libatomic} ${bpath}/libatomic.tar.gz" | sha256sum -c -
curl -L "${source_headers}${version_headers}.tar.gz" -o "${bpath}/headers.tar.gz" && \
  echo "${sha256_headers} ${bpath}/headers.tar.gz" | sha256sum -c -
cd "$bpath"
git clone $source_zlib --branch gcc.amd64
git clone --depth=1 --recurse-submodules $source_brotli
git clone --recursive $source_quiche

# Expand the source files
cd "$bpath"
for archive in ./*.tar.gz; do
  tar xzf "$archive"
done

# Clean up source files
rm -rf \
  "$GNUPGHOME" \
  "$bpath"/*.tar.*

# Create NGINX cache directories if they do not already exist
if [ ! -d "/var/cache/nginx/" ]; then
  mkdir -p \
    /var/cache/nginx/client_temp \
    /var/cache/nginx/proxy_temp \
    /var/cache/nginx/fastcgi_temp \
    /var/cache/nginx/uwsgi_temp \
    /var/cache/nginx/scgi_temp \
    /var/cache/nginx/ram_cache
fi

# We add sites-* folders as some use them. /etc/nginx/conf.d/ is the vhost folder by defaultnginx
if [[ ! -d /etc/nginx/sites-available ]]; then
	mkdir -p /etc/nginx/sites-available
	cp "$path/conf/plex.domain.tld" "/etc/nginx/sites-available/plex.domain.tld"
fi
if [[ ! -d /etc/nginx/sites-enabled ]]; then
	mkdir -p /etc/nginx/sites-enabled
fi

if [[ ! -e /etc/nginx/nginx.conf ]]; then
	mkdir -p /etc/nginx
	cd /etc/nginx || exit 1
	cp "$path/conf/nginx.conf" "/etc/nginx/nginx.conf"
fi

# Add NGINX group and user if they do not already exist
id -g nginx &>/dev/null || addgroup --system nginx
id -u nginx &>/dev/null || adduser --disabled-password --system --home /var/cache/nginx --shell /sbin/nologin --group nginx

# Test to see if our version of gcc supports __SIZEOF_INT128__
if gcc -dM -E - </dev/null | grep -q __SIZEOF_INT128__
then
  ecflag="enable-ec_nistp_64_gcc_128"
else
  ecflag=""
fi

### make libatomic
cd "$bpath/libatomic_ops-$version_libatomic"
autoreconf -i
./configure
make -j "$(nproc)"
make install

# make zlib
cd "$bpath/zlib"
./configure
make -j "$(nproc)"

### make jemalloc
cd "$bpath"
git clone https://github.com/jemalloc/jemalloc
cd "$bpath/jemalloc"
./autogen.sh
make -j "$(nproc)"
make install
ldconfig

# Build NGINX, with various modules included/excluded; requires GCC 10+
cd "$bpath/$version_nginx"
patch -p1  < "$path/patches/nginx_with_quic.patch"
patch -p1  < "$path/patches/Enable_BoringSSL_OCSP.patch"
patch -p1  < "$path/patches/use_openssl_md5_sha1.patch"
patch -p1  < "$path/patches/nginx-1.14.x-1.17.x-ngx_http_header_filter_module.c.patch"
patch -p1  < "$path/patches/nginx-1.14.x-1.17.x-ngx_http_special_response.c.patch"
patch -p1  < "$path/patches/nginx-1.14.x-1.17.x-ngx_http_v2_filter_module.c.patch"

./configure \
  --build="$time-debian-quiche-$(git --git-dir=../quiche/.git rev-parse --short HEAD)" \
  --prefix=/etc/nginx \
  --with-cc-opt="-I/usr/local/include -m64 -march=native -DTCP_FASTOPEN=23 -g -O3 -Wno-error=strict-aliasing -fstack-protector-strong --param=ssp-buffer-size=4 -Wformat -Werror=format-security -Wimplicit-fallthrough=0 -fcode-hoisting -Wno-format-extra-args -Wp,-D_FORTIFY_SOURCE=2 -Wno-deprecated-declarations" \
  --with-ld-opt="-Wl,-E -L/usr/local/lib -ljemalloc -Wl,-z,relro -Wl,-rpath,/usr/local/lib" \
  --with-pcre="$bpath/$version_pcre" \
  --with-zlib="$bpath/zlib" \
  --sbin-path=/usr/sbin/nginx \
  --modules-path=/usr/lib/nginx/modules \
  --conf-path=/etc/nginx/nginx.conf \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --pid-path=/var/run/nginx.pid \
  --lock-path=/var/run/nginx.lock \
  --http-client-body-temp-path=/var/cache/nginx/client_temp \
  --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
  --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
  --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
  --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
  --user=nginx \
  --group=nginx \
  --with-file-aio \
  --with-threads \
  --with-libatomic \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-http_v3_module \
  --with-http_realip_module \
  --with-openssl="$bpath/quiche/deps/boringssl" \
  --with-quiche="$bpath/quiche" \
  --add-module="$bpath/ngx_brotli" \
  --add-module="$bpath/headers-more-nginx-module-$version_headers" \
  --without-http_charset_module \
  --without-http_ssi_module \
  --without-http_auth_basic_module \
  --without-http_mirror_module \
  --without-http_autoindex_module \
  --without-http_userid_module \
  --without-http_geo_module \
  --without-http_split_clients_module \
  --without-http_referer_module \
  --without-http_fastcgi_module \
  --without-http_uwsgi_module \
  --without-http_scgi_module \
  --without-http_grpc_module \
  --without-http_memcached_module \
  --without-http_limit_conn_module \
  --without-http_limit_req_module \
  --without-http_empty_gif_module \
  --without-http_browser_module \
  --without-http_upstream_hash_module \
  --without-http_upstream_ip_hash_module \
  --without-http_upstream_least_conn_module \
  --without-http_upstream_zone_module \
  --without-mail_imap_module \
  --without-mail_pop3_module \
  --without-mail_smtp_module

make -j "$(nproc)"
make install
checkinstall --install=no -y
cp $bpath/$version_nginx/*.deb "$path/package"
make clean
strip -s /usr/sbin/nginx*

# Create NGINX systemd service file if it does not already exist
if [ ! -e "/lib/systemd/system/nginx.service" ]; then
  # Control will enter here if the NGINX service doesn't exist.
  file="/lib/systemd/system/nginx.service"

  /bin/cat >$file <<'EOF'
[Unit]
Description=A high performance web server and a reverse proxy server
After=network.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecStartPost=/bin/sleep 0.1
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
fi

echo "All done."