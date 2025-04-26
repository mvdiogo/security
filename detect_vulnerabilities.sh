#!/bin/bash
# Detecção de vulnerabilidades instaladas

echo "🔍 Iniciando verificação de vulnerabilidades..."

# SSH
echo -n "[SSH] Root login permitido: "; grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config && echo "VULNERÁVEL" || echo "OK"
echo -n "[SSH] Limite alto de tentativas: "; grep -q "MaxAuthTries 10" /etc/ssh/sshd_config && echo "VULNERÁVEL" || echo "OK"

# FTP
echo -n "[FTP] Acesso anônimo permitido: "; grep -q "anonymous_enable=YES" /etc/vsftpd.conf && echo "VULNERÁVEL" || echo "OK"
echo -n "[FTP] SSL/TLS desabilitado: "; grep -q "ssl_enable=NO" /etc/vsftpd.conf && echo "VULNERÁVEL" || echo "OK"

# Samba
echo -n "[Samba] Compartilhamento guest: "; grep -q "guest ok = yes" /etc/samba/smb.conf && echo "VULNERÁVEL" || echo "OK"
echo -n "[Samba] Permissões 777 detectadas: "; ls -l /srv/samba/ | grep -q drwxrwxrwx && echo "VULNERÁVEL" || echo "OK"

# Apache
echo -n "[Apache] Directory Listing habilitado: "; grep -q "Options Indexes" /etc/apache2/apache2.conf && echo "VULNERÁVEL" || echo "OK"
echo -n "[Apache] phpinfo() exposto: "; [ -f /var/www/html/info.php ] && echo "VULNERÁVEL" || echo "OK"
echo -n "[Apache] Exposição de versão: "; curl -Is http://localhost | grep -q "Server:" && echo "VULNERÁVEL" || echo "OK"

# MySQL
echo -n "[MySQL] Root sem senha: "; mysqladmin ping -uroot --password= 2>/dev/null && echo "VULNERÁVEL" || echo "OK"
echo -n "[MySQL] Banco de dados 'test' presente: "; mysql -uroot -e "SHOW DATABASES;" | grep -q testdb && echo "VULNERÁVEL" || echo "OK"

# PostgreSQL
echo -n "[PostgreSQL] Trust authentication ativa: "; grep -q "local\s\+all\s\+all\s\+trust" /etc/postgresql/*/main/pg_hba.conf && echo "VULNERÁVEL" || echo "OK"
echo -n "[PostgreSQL] Escutando em todas interfaces: "; grep -q "listen_addresses = '*'" /etc/postgresql/*/main/postgresql.conf && echo "VULNERÁVEL" || echo "OK"

# Redis
echo -n "[Redis] Sem senha configurada: "; grep -q "^# requirepass" /etc/redis/redis.conf && echo "VULNERÁVEL" || echo "OK"
echo -n "[Redis] Exposto em 0.0.0.0: "; grep -q "bind 0.0.0.0" /etc/redis/redis.conf && echo "VULNERÁVEL" || echo "OK"

# Telnet
echo -n "[Telnet] Serviço Telnet ativo: "
if netstat -tuln | grep -q ":23 "; then
  echo "VULNERÁVEL"
else
  echo "OK"
fi


# NFS
echo -n "[NFS] Export inseguro detectado: "; grep -q "\*" /etc/exports && echo "VULNERÁVEL" || echo "OK"

# SNMP
echo -n "[SNMP] Comunidade pública ativa: "; grep -q "rocommunity public" /etc/snmp/snmpd.conf && echo "VULNERÁVEL" || echo "OK"

# PHP
echo -n "[PHP] Exibição de erros ativa: "; grep -q "display_errors = On" /etc/php/*/apache2/php.ini && echo "VULNERÁVEL" || echo "OK"

echo "✅ Verificação concluída!"
