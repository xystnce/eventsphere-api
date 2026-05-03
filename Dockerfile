FROM dunglas/frankenphp
RUN install-php-extensions pdo pdo_mysql mysqlnd
COPY . /app
EXPOSE 80
