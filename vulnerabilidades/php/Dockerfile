FROM php:8.0-apache

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    sqlite3 \
    libsqlite3-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Instalar extensões do PHP
RUN docker-php-ext-install \
    pdo \
    pdo_mysql \
    pdo_sqlite \
    mysqli \
    mbstring \
    exif \
    pcntl \
    bcmath \
    gd

# Habilitar mod_rewrite do Apache
RUN a2enmod rewrite

# Configurar Apache para porta 8000
RUN echo "Listen 8000" >> /etc/apache2/ports.conf
RUN sed -i 's/<VirtualHost \*:80>/<VirtualHost \*:8000>/' /etc/apache2/sites-available/000-default.conf
RUN sed -i 's/:80>:8000>/:8000>/' /etc/apache2/sites-available/000-default.conf

# Copiar arquivo da aplicação
COPY index.php /var/www/html/

# Criar diretório para logs e dar permissões
RUN mkdir -p /tmp && chmod 777 /tmp

# Configurar permissões
RUN chown -R www-data:www-data /var/www/html

EXPOSE 8000

CMD ["apache2-foreground"]