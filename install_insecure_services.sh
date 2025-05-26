#!/bin/bash
# Script para configurar serviços vulneráveis
# Desenvolvido para ambiente de laboratório de segurança

set -e  # Stop execution on error

echo "🔧 Configurando serviços vulneráveis..."

# --- SSH (Configuração Insegura) ---
echo "🔧 Configurando SSH de forma insegura..."
cat > /etc/ssh/sshd_config << EOF
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
# HostKey /etc/ssh/ssh_host_dsa_key # <--- COMMENT OUT OR REMOVE THIS LINE
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
# UsePrivilegeSeparation yes # <--- REMOVE OR COMMENT OUT THIS LINE
# KeyRegenerationInterval 3600 # <--- REMOVE OR COMMENT OUT THIS LINE
# ServerKeyBits 1024 # <--- REMOVE OR COMMENT OUT THIS LINE
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
PasswordAuthentication yes
StrictModes no
# RSAAuthentication yes # <--- REMOVE OR COMMENT OUT THIS LINE
PubkeyAuthentication yes
IgnoreRhosts no
# RhostsRSAAuthentication no # <--- REMOVE OR COMMENT OUT THIS LINE
HostbasedAuthentication no
PermitEmptyPasswords yes
ChallengeResponseAuthentication no
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
MaxAuthTries 100
ClientAliveInterval 0
ClientAliveCountMax 3
UsePAM yes
EOF
# Ensure SSH host keys are generated (this will now generate RSA, ECDSA, ED25519)
ssh-keygen -A

# --- FTP (vsftpd - Configuração Insegura) ---
echo "🔧 Configurando FTP de forma insegura..."
cat > /etc/proftpd/proftpd.conf << EOF
<Anonymous ~ftp>
  User                    ftp
  Group                   nogroup
  UserAlias               anonymous ftp
  RequireValidShell       no
  DirFakeUser             on ftp
  DirFakeGroup            on ftp

  <Directory *>
    <Limit WRITE>
      DenyAll
    </Limit>
  </Directory>

  # Allow uploads (optional)
  <Directory /srv/ftp/incoming>
    <Limit STOR>
      AllowAll
    </Limit>
  </Directory>
</Anonymous>
EOF


echo "Arquivo de teste FTP" > /srv/ftp/test.txt
chmod 666 /srv/ftp/test.txt

# --- Samba (Configuração Insegura) ---
echo "🔧 Configurando Samba de forma insegura..."
cat > /etc/samba/smb.conf << EOF
[global]
workgroup = WORKGROUP
server string = Vulnerable Samba Server
netbios name = VULNERABLE
security = user
map to guest = bad user
dns proxy = no
log file = /var/log/samba/log.%m
max log size = 1000
syslog = 0
panic action = /usr/share/samba/panic-action %d
server role = standalone server
passdb backend = tdbsam
obey pam restrictions = yes
unix password sync = yes
passwd program = /usr/bin/passwd %u
passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
pam password change = yes
usershare allow guests = yes # Ensure this is enabled for guest shares
guest account = nobody

[insecure_share]
comment = Insecure Share
path = /srv/samba/insecure_share
browseable = yes
read only = no
guest ok = yes
create mask = 0777
directory mask = 0777
force user = nobody
force group = nogroup
EOF

echo "Arquivo compartilhado inseguro" > /srv/samba/insecure_share/secret.txt
chmod 666 /srv/samba/insecure_share/secret.txt

# --- Apache (Configuração Insegura) ---
echo "🔧 Configurando Apache de forma insegura..."
echo "ServerName localhost" | tee /etc/apache2/conf-available/servername.conf
cat > /etc/apache2/sites-enabled/000-default.conf << EOF
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
    
    <Directory /var/www/html>
        Options Indexes FollowSymLinks MultiViews ExecCGI
        AllowOverride All
        Require all granted
        DirectoryIndex index.html index.php
    </Directory>
</VirtualHost>
EOF
a2enconf servername

# Create vulnerable pages
echo "<?php phpinfo(); ?>" > /var/www/html/info.php
cat > /var/www/html/login.php << 'EOF'
<?php
if(isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // SQL Injection vulnerável
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    echo "<h3>Query executada: $query</h3>";
    
    // Simulação de autenticação
    if($username == "admin" && $password == "admin") {
        echo "<h2>Login realizado com sucesso!</h2>";
    } else {
        echo "<h2>Credenciais inválidas</h2>";
    }
}
?>
<html>
<head><title>Login Vulnerável</title></head>
<body>
<h1>Sistema de Login Vulnerável</h1>
<form method="POST">
    Username: <input type="text" name="username"><br><br>
    Password: <input type="password" name="password"><br><br>
    <input type="submit" value="Login">
</form>
</body>
</html>
EOF

cat > /var/www/html/upload.php << 'EOF'
<?php
if(isset($_FILES['file'])) {
    $target_dir = "/var/www/html/uploads/";
    if (!file_exists($target_dir)) {
        mkdir($target_dir, 0777, true);
    }
    
    $target_file = $target_dir . basename($_FILES["file"]["name"]);
    
    // Upload vulnerável - sem validação
    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        echo "Arquivo " . basename($_FILES["file"]["name"]) . " foi enviado com sucesso.";
    } else {
        echo "Erro no upload.";
    }
}
?>
<html>
<head><title>Upload Vulnerável</title></head>
<body>
<h1>Upload de Arquivos (Vulnerável)</h1>
<form action="" method="post" enctype="multipart/form-data">
    Selecione o arquivo:
    <input type="file" name="file" id="file">
    <input type="submit" value="Upload" name="submit">
</form>
</body>
</html>
EOF

mkdir -p /var/www/html/uploads
chmod 777 /var/www/html/uploads


# --- MariaDB (Configuração Insegura) ---
echo "🔧 Configurando MariaDB de forma insegura..."
# Overwrite default config with insecure one
cat > /etc/mysql/mariadb.conf.d/50-server.cnf << EOF
[server]
[mysqld]
user = mysql
pid-file = /run/mysqld/mysqld.pid
socket = /run/mysqld/mysqld.sock
basedir = /usr
datadir = /var/lib/mysql
tmpdir = /tmp
lc-messages-dir = /usr/share/mysql
bind-address = 0.0.0.0
query_cache_size = 16M
log_error = /var/log/mysql/error.log
expire_logs_days = 10
character-set-server = utf8mb4
collation-server = utf8mb4_general_ci

# Insecure settings
skip-networking=0
skip-name-resolve
EOF

# --- PostgreSQL (Configuração Insegura) ---
echo "🔧 Configurando PostgreSQL de forma insegura..."
# Ensure postgresql.conf exists before editing
if [ ! -f "/etc/postgresql/15/main/postgresql.conf" ]; then
    echo "PostgreSQL config file not found, this might cause issues."
    # Attempt to initialize a minimal config if it's missing (unlikely after apt install)
    # pg_ctlcluster 15 main initdb || true
fi
sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/15/main/postgresql.conf
sed -i "s/#port = 5432/port = 5432/" /etc/postgresql/15/main/postgresql.conf

cat > /etc/postgresql/15/main/pg_hba.conf << EOF
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                trust
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
host    all             all             0.0.0.0/0               trust
host    all             all             ::/0                    trust
EOF

# --- Redis (Configuração Insegura) ---
echo "🔧 Configurando Redis de forma insegura..."
cat > /etc/redis/redis.conf << EOF
bind 0.0.0.0
protected-mode no
port 6379
timeout 0
# keepalive 300 # <--- REMOVE OR COMMENT OUT THIS LINE
tcp-keepalive 300 # <--- ADD THIS LINE FOR TCP KEEPALIVES, OR REMOVE IF NOT NEEDED
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16
save 900 1
save 300 10
save 60 10000
rdbcompression yes
dbfilename dump.rdb
dir /var/lib/redis
maxmemory-policy noeviction
EOF

# --- SNMP (Configuração Insegura) ---
echo "🔧 Configurando SNMP de forma insegura..."
cat > /etc/snmp/snmpd.conf << EOF
agentAddress udp:161,udp6:[::1]:161
view systemonly included .1.3.6.1.2.1.1
view systemonly included .1.3.6.1.2.1.25.1
rocommunity public default -V systemonly
rocommunity public
rouser authOnlyUser
sysLocation Vulnerable Lab
sysContact Admin <admin@vulnerable.lab>
sysServices 72
proc mountd
proc ntalkd 4
proc sendmail 10 1
disk / 10000
disk /var 5%
includeAllDisks 10%
load 12 10 5
extend test1 /bin/echo Hello, world!
extend-sh test2 echo Hello, world! ; echo Hi there ; exit 35
EOF

# --- NFS (Configuração Insegura) ---
echo "🔧 Configurando NFS de forma insegura..."
cat > /etc/exports << EOF
/srv/nfs/insecure_share *(rw,sync,no_subtree_check,no_root_squash,insecure,all_squash,anonuid=0,anongid=0)
EOF

echo "Arquivo NFS compartilhado" > /srv/nfs/insecure_share/nfs_file.txt
chmod 666 /srv/nfs/insecure_share/nfs_file.txt

# --- Telnet (Configuração via inetd) ---
echo "🔧 Configurando Telnet..."
# inetd will be started by supervisord, and it will read this config
# No explicit start needed here, just the config file creation.
if ! grep -q "telnet stream tcp nowait telnetd /usr/sbin/tcpd /usr/sbin/in.telnetd" /etc/inetd.conf; then
    echo "telnet stream tcp nowait telnetd /usr/sbin/tcpd /usr/sbin/in.telnetd" >> /etc/inetd.conf
fi

# --- PHP (Configuração Insegura) ---
echo "🔧 Configurando PHP de forma insegura..."
PHP_INI=$(find /etc/php -name "php.ini" | grep apache2 | head -1)
if [ -z "$PHP_INI" ]; then
    # Fallback if apache2 php.ini isn't found, try CLI or general
    PHP_INI=$(find /etc/php -name "php.ini" | head -1)
fi

if [ -n "$PHP_INI" ]; then
    sed -i 's/display_errors = Off/display_errors = On/' "$PHP_INI"
    sed -i 's/display_startup_errors = Off/display_startup_errors = On/' "$PHP_INI"
    sed -i 's/log_errors = On/log_errors = Off/' "$PHP_INI"
    sed -i 's/allow_url_include = Off/allow_url_include = On/' "$PHP_INI"
    sed -i 's/file_uploads = On/file_uploads = On/' "$PHP_INI"
    sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=1/' "$PHP_INI"
fi

echo "✅ Configuração de serviços vulneráveis concluída!"
echo "⚠️  ATENÇÃO: Este sistema contém configurações inseguras intencionais!"
echo "📋 Serviços configurados:"
echo "   - SSH (porta 22) - root:root123, testuser:password123"
echo "   - FTP (porta 21) - anonymous permitido"
echo "   - HTTP (porta 80) - páginas vulneráveis disponíveis"
echo "   - MySQL (porta 3306) - sem senha para root"
echo "   - PostgreSQL (porta 5432) - autenticação trust"
echo "   - Redis (porta 6379) - sem autenticação"
echo "   - Samba (portas 139/445) - compartilhamento guest"
echo "   - SNMP (porta 161) - community string 'public'"
echo "   - NFS (porta 2049) - exportação insegura"
echo "   - Telnet (porta 23) - habilitado"