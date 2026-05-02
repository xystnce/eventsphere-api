FROM php:8.3-apache
RUN a2dismod mpm_event mpm_worker && a2enmod mpm_prefork
RUN docker-php-ext-install mysqli
COPY . /var/www/html/
EXPOSE 80
