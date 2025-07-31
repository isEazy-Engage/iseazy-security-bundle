FROM php:8.4-fpm

RUN apt-get update \
    && apt-get install -y \
        libicu-dev libzip-dev \
        libpq-dev \
        librabbitmq-dev \
        curl \
        libcurl4-openssl-dev \
        zip \
	    vim

RUN docker-php-ext-install intl \
        && docker-php-ext-install curl \
        && docker-php-ext-install zip \
        && docker-php-ext-install pdo_pgsql

COPY .docker/php/xdebug.ini /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini
RUN pecl install amqp xdebug && docker-php-ext-enable amqp opcache xdebug

RUN echo "alias ll='ls -ltha'" >> ~/.bashrc

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

WORKDIR /app

CMD ["php-fpm"]
