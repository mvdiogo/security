#!/bin/bash
# Instalação de serviços vulneráveis para ambiente Docker
# Adaptado para containers sem systemd

echo "🔧 Atualizando sistema..."
apt update -y && apt install -y openssh-server vsftpd samba apache2 mariadb-server postgresql redis-server telnetd nfs-kernel-server php libapache2-mod-php snmp snmpd curl nmap net-tools vim wget

# Criar diretórios necessários
mkdir -p /srv/samba/insecure_share
mkdir -p /srv/nfs/insecure_share
chmod 777 /srv/samba/insecure_share
chmod 777 /srv/nfs/insecure_share

# --- SSH ---
echo "🔧 Configurando SSH..."
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
echo "MaxAuthTries 10" >> /etc/ssh/sshd_config

# Startar o SSH manualmente
/usr/sbin/sshd

# --- FTP (vsftpd) ---
echo "🔧 Configurando FTP..."
sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf
sed -i 's/#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf
sed -i 's/ssl_enable=YES/ssl_enable=NO/' /etc/vsftpd.conf

# Startar FTP manualmente
/usr/sbin/vsftpd &

# --- Samba ---
echo "🔧 Configurando Samba..."
cat <<EOF >> /etc/samba/smb.conf

[insecure_share]
   path = /srv/samba/insecure_share
   browsable = yes
   read only = no
   guest ok = yes
EOF

# Startar Samba manualmente
/usr/sbin/smbd &

# --- Apache ---
echo "🔧 Configurando Apache..."
echo "<?php phpinfo(); ?>" > /var/www/html/info.php
sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf
sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/s/Options FollowSymLinks/Options Indexes FollowSymLinks/' /etc/apache2/apache2.conf

# Startar Apache manualmente
apachectl start

# --- MariaDB ---
echo "🔧 Configurando MariaDB..."
mysqld_safe --skip-networking=0 & sleep 5

mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY ''; FLUSH PRIVILEGES;"
mysql -u root -e "CREATE DATABASE testdb;"

# --- PostgreSQL ---
echo "🔧 Configurando PostgreSQL..."
sed -i 's/^local\s\+all\s\+postgres\s\+peer/local all postgres trust/' /etc/postgresql/*/main/pg_hba.conf
sed -i 's/^local\s\+all\s\+all\s\+peer/local all all trust/' /etc/postgresql/*/main/pg_hba.conf
sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/*/main/postgresql.conf

# Startar PostgreSQL manualmente
su postgres -c "/usr/lib/postgresql/15/bin/pg_ctl -D /var/lib/postgresql/15/main start"

# --- Redis ---
echo "🔧 Configurando Redis..."
sed -i 's/^bind 127.0.0.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf
sed -i '/^# requirepass/d' /etc/redis/redis.conf

# Startar Redis manualmente
redis-server /etc/redis/redis.conf &

# --- Telnet ---
echo "🔧 Configurando Telnet..."
/etc/init.d/openbsd-inetd restart || true

# --- NFS ---
echo "🔧 Configurando NFS..."
echo "/srv/nfs/insecure_share *(rw,sync,no_subtree_check,no_root_squash)" > /etc/exports
exportfs -ra

# --- SNMP ---
echo "🔧 Configurando SNMP..."
echo "rocommunity public" > /etc/snmp/snmpd.conf

# Startar SNMP manualmente
snmpd -f &

# --- PHP ---
echo "🔧 Configurando PHP..."
sed -i 's/display_errors = Off/display_errors = On/' /etc/php/*/apache2/php.ini

echo "✅ Todos os serviços foram instalados e iniciados de forma insegura!"
