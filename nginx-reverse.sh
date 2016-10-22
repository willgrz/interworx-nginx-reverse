#!/bin/bash -x
#adds nginx reverse proxy on SSL add in interworx and installs a wildcard reverse proxy on port 80 (all IPs)
#the backend domain is resolved against the local interworx DNS so it ends up on the correct IP regardless of nginx listening on all IPs
#this tool requires a basic nginx configuration which can be done on any centos 6/7 based system with the -install action
#Existing domains can be imported with the "-import" action
#SEE README BEFORE RUNNING ANYTHING

#configuration
##dir for configs of nginx
revconf="/etc/nginx/conf.d/reverse/"
##log file
log="/var/log/iworx-add-nginx.log"

#set action
action=$1
#fix var if needed
if [ -z "$iw_domainname" ]; then
  iw_domainname="$iw_domain"
fi
#set some legacy other named VARs
dom=$iw_domainname
#add port if needed, else 443 standard
srcpass="$dom"

if [ -z "$iw_uniqname" ] && [ "$action" == "del" ]; then
  if [ ! -f "/home/"*"/var/${dom}/ssl/${dom}.crt" ] && [ -d /home/*/var/${dom}/ ]; then
    iw_uniqname=$(find /home/*/var/${dom}/ssl/ | head -1 |  awk -F'/' '{print $3}')
  else
    echo "Failed to get homedir - exiting" >>$log
    exit 1
  fi
fi

if [ -z "$iw_uniqname" ] && [ "$action" == "new" ]; then
  out=$(ls /home/*/var/${dom}/ssl/${dom}.crt | wc -l)
  if [ "$out" == "1" ]; then
    iw_uniqname=$(ls /home/*/var/${dom}/ssl/${dom}.crt | awk -F'/' '{print $3}')
  else
    echo "crash on username assembly" >>$log
    echo "/home/*/var/${dom}/ssl/${dom}.crt" >>$log
    exit 1
  fi
fi

echo "started for $dom on $(date)" >>$log
if [ "$action" == "new" ]; then
  echo "sleeping 10s to avoid race condition" >>$log
  sleep 10
fi


function create_rev {
if [ -f "/home/${iw_uniqname}/var/${dom}/ssl/${dom}.crt" ] && [ ! -f "/home/${iw_uniqname}/var/${dom}/ssl/${dom}.crt.chain" ]; then
  cat /home/${iw_uniqname}/var/${dom}/ssl/${dom}.crt /home/${iw_uniqname}/var/${dom}/ssl/${dom}.chain.crt >/home/${iw_uniqname}/var/${dom}/ssl/${dom}.crt.chain
elif [ ! -f "/home/${iw_uniqname}/var/${dom}/ssl/${dom}.crt" ]; then
  echo "no cert for domain - exiting" >>$log
  echo "/home/${iw_uniqname}/var/${dom}/ssl/${dom}.crt" >>$log
  exit 1
fi
    #echo default conf into file
    cat << 'EOF' >> $revconf/$dom.conf
#SERVER FOR ZDOMAIN
server {
    listen 8443 ssl;
    listen 8080;
    server_name ZDOMAIN www.ZDOMAIN;
    ssl_certificate           ZSCERT;
    ssl_certificate_key       ZSKEY;
    ssl on;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    #add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    ssl_session_tickets off;
    resolver 127.0.0.1 valid=300s;
    resolver_timeout 10s;
    access_log /var/log/nginx/reverse/ZDOMAIN.access.log;
    error_log /var/log/nginx/reverse/ZDOMAIN.error.log;
    location / {
      proxy_set_header        Host $host;
      proxy_set_header        X-Real-IP $remote_addr;
      proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header        X-Forwarded-Proto $scheme;
      proxy_pass https://SRCPASS;
      proxy_read_timeout  180;
    }
}
EOF
    #default rpls
    sed -i "s/ZDOMAIN/$dom/g" $revconf/$dom.conf
    sed -i "s/ZSCERT/\/home\/${iw_uniqname}\/var\/${dom}\/ssl\/${dom}.crt.chain/" $revconf/$dom.conf
    sed -i "s/ZSKEY/\/home\/${iw_uniqname}\/var\/${dom}\/ssl\/${dom}.priv.key/" $revconf/$dom.conf
    sed -i "s/SRCPASS/$srcpass/" $revconf/$dom.conf
     #done
     sleep 3
     sudo /etc/init.d/nginx reload
     echo "Done: Reverse Proxy for $dom set up" >>$log
}


if [ "$action" == "new" ]; then
  create_rev
elif [ "$action" == "del" ]; then
  if [ ! -f "$revconf/$dom.conf" ]; then
    echo "No configuration for $dom found - exiting"
    exit 0
  fi
  rm -rf /home/${iw_uniqname}/var/${dom}/ssl/${dom}.crt.chain
  sudo /usr/sbin/chownwww
  rm -rf $revconf/$dom.conf
  sudo /etc/init.d/nginx reload
  echo "$dom removed" >>$log
  exit 0
elif [ "$action" == "-import" ]; then
  if [ "$(id -u)" != "0" ]; then
      echo "Import script must be ran as root" 2>&1
      exit 1
  fi
  for crt in $(find /home/*/var/*/ssl/*.crt | grep -v "chain.crt"); do
    dom="$(echo "$crt" |awk -F'/' '{print $5}')"
    iw_domainname="$dom"
    srcpass="$dom"
    iw_uniqname="$(echo "$crt" |awk -F'/' '{print $3}')"
    create_rev
  done
elif [ "$action" == "-install" ]; then
  if [ "$(id -u)" != "0" ]; then
      echo "Install script must be ran as root" 2>&1
      exit 1
  fi
  echo "Installing nginx via source in /usr/src/nginx/ - config is /etc/nginx/"
  echo "Installing yum packages needed"
  yum -y install gcc gcc-c++ make zlib-devel pcre-devel openssl-devel
  mkdir /usr/src/nginx && cd /usr/src/nginx
  echo "Downloading nginx source"
  wget -q https://nginx.org/download/nginx-1.11.5.tar.gz
  tar xvfz nginx-1.11.5.tar.gz
  echo "configure with: "
  echo "./configure --user=nginx --group=nginx --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --with-http_realip_module --with-file-aio --with-pcre --with-http_ssl_module --with-http_stub_status_module --with-http_gzip_static_module --conf-path=/etc/nginx/nginx.conf --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log"
    ./configure --user=nginx --group=nginx --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --with-http_realip_module --with-file-aio --with-pcre --with-http_ssl_module --with-http_stub_status_module --with-http_gzip_static_module --conf-path=/etc/nginx/nginx.conf --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log
    echo "adding user nginx"
    useradd -r nginx
    echo "mkdir /etc/nginx and /var/log/nginx"
    mkdir /var/log/nginx
    mkdir /etc/nginx
    echo "make now"
    make
    echo "make install"
    make install
    echo "get init script from github"
    wget -q -O /etc/init.d/nginx https://gist.github.com/sairam/5892520/raw/b8195a71e944d46271c8a49f2717f70bcd04bf1a/etc-init.d-nginx
    echo "chmod"
    chmod +x /etc/init.d/nginx
    echo "chkconfig for startup"
    chkconfig --add nginx
    chkconfig --level 345 nginx on
    echo "add new config"
cat << 'EOF' >/etc/nginx/nginx.conf
user nginx;
worker_processes 8;
pid /var/run/nginx.pid;

events {
  worker_connections 1024;
}

http {
client_max_body_size 100M;
set_real_ip_from 199.27.128.0/21;
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/12;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
real_ip_header CF-Connecting-IP;
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  server_tokens off;
  server_names_hash_bucket_size 96;
  server_names_hash_max_size 128;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_dhparam /etc/ssl/certs/dhparam.pem;
  ssl_prefer_server_ciphers on;
  log_format vhosts '$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
  access_log /var/log/nginx/main.access.log;
  error_log /var/log/nginx/main.error.log;
  gzip on;
  gzip_disable "msie6";
  include /etc/nginx/conf.d/local/*.conf;
  include /etc/nginx/conf.d/reverse/*.conf;
    include /etc/nginx/conf.d/redirect/*.conf;
  include /etc/nginx/conf.d/system/*.conf;
  include /etc/nginx/conf.d/special/*.conf;
}
EOF
echo "Adding wildcard reverse proxy configuarion"
cat << 'EOF' >/etc/nginx/conf.d/reverse/wildcard.conf
server {
    listen 8080;
    server_name _;
    location / {
      proxy_set_header        Host $host;
      proxy_set_header        X-Real-IP $remote_addr;
      proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header        X-Forwarded-Proto $scheme;
      proxy_pass http://$host;
      resolver 127.0.0.1 valid=300s;
      resolver_timeout 10s;
      proxy_read_timeout  180;
    }
}
EOF
echo "Adding script /usr/sbin/chownwww for deletion as iworx user"
cat << 'EOF' >/usr/sbin/chownwww
#!/bin/sh
chown -R iworx:iworx /etc/nginx/conf.d/reverse/*.conf
EOF
chmod +x /usr/sbin/chownwww
service nginx restart
echo "You need to add this sudoers entries:"
echo '%iworx ALL=NOPASSWD:/usr/sbin/service nginx reload'
echo '%iworx ALL=NOPASSWD:/usr/sbin/chownwww'
echo 'Defaults:iworx !requiretty'
echo "You need to set iptables rules for port 80 and 443 to re-route external traffic on this ports to internal interworx Apache on 80/443"
echo "80 has as wildcard reverse proxy no issues, 443 requires SSL set up on all domains within nginx or will error"
echo "iptables -t nat -I PREROUTING ! -i lo -p tcp --dport 80 -j REDIRECT --to-port 8080"
echo "iptables -t nat -I PREROUTING ! -i lo -p tcp --dport 443 -j REDIRECT --to-port 8443"
exit 0
else
  echo "no action specified - exiting" >>$log
  exit 1
fi
