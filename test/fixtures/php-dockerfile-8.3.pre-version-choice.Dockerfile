FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends libfreetype6-dev libjpeg62-turbo-dev libldap2-dev libpng-dev libwebp-dev libzip-dev \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp
RUN docker-php-ext-configure ldap --with-libdir="lib/$(dpkg-architecture --query DEB_BUILD_MULTIARCH)"
RUN docker-php-ext-install -j"$(nproc)" gd ldap zip

RUN echo "APPCRANE WARNING: composer.json requires ext-redis, which AppCrane's generated PHP build cannot install (it is not bundled with PHP - most likely a PECL extension such as redis, imagick or memcached). The image is built WITHOUT it and the app may fail at runtime. Commit your own Dockerfile if you need it."

# AppCrane listens on $PORT, not 80. Apache expands ${PORT} from the environment.
ENV PORT=3000
RUN set -eux; \
    printf '%s\n' 'Listen ${PORT}' 'ServerName localhost' > /etc/apache2/ports.conf; \
    printf '%s\n' '<VirtualHost *:${PORT}>' '  ServerName localhost' '  DocumentRoot /var/www/html/public' '  <Directory /var/www/html/public>' '    Options -Indexes +FollowSymLinks' '    AllowOverride All' '    Require all granted' '  </Directory>' '  ErrorLog /proc/self/fd/2' '  CustomLog /proc/self/fd/1 combined' '</VirtualHost>' > /etc/apache2/sites-available/000-default.conf; \
    a2enmod rewrite

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV COMPOSER_HOME=/tmp/composer
ENV COMPOSER_ALLOW_SUPERUSER=1

WORKDIR /var/www/html
COPY . .

RUN composer install --no-dev --prefer-dist --no-interaction --ignore-platform-req=ext-redis

# AppCrane supply-chain checks for the repo root (PHP)
RUN echo "APPCRANE SUPPLY-CHAIN WARNING: no composer.lock in the repo root - this image was built by re-resolving every dependency and is NOT reproducible. Commit composer.lock. Set APPCRANE_REQUIRE_LOCKFILE=1 on the AppCrane host to make this fatal instead of a warning."
RUN composer audit --no-interaction > /tmp/appcrane-audit.txt 2>&1 && echo "APPCRANE AUDIT: no known advisories in the repo root." || { echo "APPCRANE AUDIT WARNING: composer audit reported advisories in the repo root, or could not run at all. Deploy NOT blocked - set APPCRANE_REQUIRE_CLEAN_AUDIT=1 on the AppCrane host to block:"; tail -n 30 /tmp/appcrane-audit.txt; }

RUN chown -R www-data:www-data /var/www/html
USER www-data

EXPOSE 3000

CMD ["apache2-foreground"]
