Copy

FROM dunglas/frankenphp
 
RUN install-php-extensions pdo pdo_mysql mysqlnd
 
COPY . /app/public
 
EXPOSE 8000
 
ENV SERVER_NAME=:8000
