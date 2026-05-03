FROM dunglas/frankenphp
 
RUN install-php-extensions pdo pdo_mysql mysqlnd
 
COPY Caddyfile /etc/caddy/Caddyfile
COPY . /app/public
 
EXPOSE 80
 
ENV SERVER_NAME=:80
