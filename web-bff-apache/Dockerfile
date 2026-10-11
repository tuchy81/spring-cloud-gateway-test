FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends apache2 libapache2-mod-auth-openidc ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN a2enmod auth_openidc proxy proxy_http headers rewrite && a2dissite 000-default
COPY web-bff.conf /etc/apache2/sites-available/web-bff.conf
RUN a2ensite web-bff
COPY html /var/www/web
CMD ["bash", "-c", ". /etc/apache2/envvars && mkdir -p $APACHE_RUN_DIR $APACHE_LOCK_DIR && exec apache2 -DFOREGROUND"]
