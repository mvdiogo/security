#!/bin/bash
# Script para gerar um relatório HTML com os resultados da verificação

OUTPUT="vulnerability_report.html"

echo "📄 Gerando relatório em $OUTPUT..."

{
echo "<!DOCTYPE html>"
echo "<html lang='pt-BR'>"
echo "<head><meta charset='UTF-8'><title>Relatório de Vulnerabilidades</title></head>"
echo "<body>"
echo "<h1>Relatório de Vulnerabilidades</h1>"
echo "<table border='1' cellspacing='0' cellpadding='5'>"
echo "<tr><th>Serviço</th><th>Vulnerabilidade</th><th>Status</th></tr>"
} > "$OUTPUT"

# Função para adicionar linha no HTML
add_row() {
  SERVICO=$1
  DESCRICAO=$2
  STATUS=$3
  echo "<tr><td>$SERVICO</td><td>$DESCRICAO</td><td><b>$STATUS</b></td></tr>" >> "$OUTPUT"
}

# Função de verificação (aproveita o detect_vulnerabilities.sh)
detect_vulns() {

# SSH
grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config && add_row "SSH" "Root login permitido" "VULNERÁVEL" || add_row "SSH" "Root login permitido" "OK"
grep -q "MaxAuthTries 10" /etc/ssh/sshd_config && add_row "SSH" "Limite alto de tentativas" "VULNERÁVEL" || add_row "SSH" "Limite alto de tentativas" "OK"

# FTP
grep -q "<Anonymous" /etc/proftpd/proftpd.conf && \
  add_row "FTP" "FTP Anônimo ativo" "VULNERÁVEL" || \
  add_row "FTP" "FTP Anônimo ativo" "OK"
(grep -q "TLSEngine on" /etc/proftpd/proftpd.conf && \
  grep -q "TLSRequired on" /etc/proftpd/proftpd.conf) && \
  add_row "FTP" "SSL/TLS desabilitado" "OK" || \
  add_row "FTP" "SSL/TLS desabilitado" "VULNERÁVEL"
# Samba
grep -q "guest ok = yes" /etc/samba/smb.conf && add_row "Samba" "Compartilhamento Guest" "VULNERÁVEL" || add_row "Samba" "Compartilhamento Guest" "OK"
ls -l /srv/samba/ | grep -q drwxrwxrwx && add_row "Samba" "Permissões 777" "VULNERÁVEL" || add_row "Samba" "Permissões 777" "OK"

# Apache
grep -q "Options Indexes" /etc/apache2/apache2.conf && add_row "Apache" "Directory Listing ativo" "VULNERÁVEL" || add_row "Apache" "Directory Listing ativo" "OK"
[ -f /var/www/html/info.php ] && add_row "Apache" "phpinfo exposto" "VULNERÁVEL" || add_row "Apache" "phpinfo exposto" "OK"

# MySQL
mysqladmin ping -uroot --password= 2>/dev/null && add_row "MySQL" "Root sem senha" "VULNERÁVEL" || add_row "MySQL" "Root sem senha" "OK"
mysql -uroot -e "SHOW DATABASES;" | grep -q testdb && add_row "MySQL" "Banco testdb aberto" "VULNERÁVEL" || add_row "MySQL" "Banco testdb aberto" "OK"

# PostgreSQL
grep -q "local\s\+all\s\+all\s\+trust" /etc/postgresql/*/main/pg_hba.conf && add_row "PostgreSQL" "Trust Authentication ativa" "VULNERÁVEL" || add_row "PostgreSQL" "Trust Authentication ativa" "OK"
grep -q "listen_addresses = '*'" /etc/postgresql/*/main/postgresql.conf && add_row "PostgreSQL" "Escutando todas interfaces" "VULNERÁVEL" || add_row "PostgreSQL" "Escutando todas interfaces" "OK"

# Redis
grep -q "^# requirepass" /etc/redis/redis.conf && add_row "Redis" "Sem senha configurada" "VULNERÁVEL" || add_row "Redis" "Sem senha configurada" "OK"
grep -q "bind 0.0.0.0" /etc/redis/redis.conf && add_row "Redis" "Exposto em 0.0.0.0" "VULNERÁVEL" || add_row "Redis" "Exposto em 0.0.0.0" "OK"

# Telnet
systemctl is-active telnet | grep -q active && add_row "Telnet" "Serviço ativo" "VULNERÁVEL" || add_row "Telnet" "Serviço ativo" "OK"

# NFS
grep -q "\*" /etc/exports && add_row "NFS" "Export inseguro" "VULNERÁVEL" || add_row "NFS" "Export inseguro" "OK"

# SNMP
grep -q "rocommunity public" /etc/snmp/snmpd.conf && add_row "SNMP" "Comunidade pública" "VULNERÁVEL" || add_row "SNMP" "Comunidade pública" "OK"

# PHP
grep -q "display_errors = On" /etc/php/*/apache2/php.ini && add_row "PHP" "Display errors ativo" "VULNERÁVEL" || add_row "PHP" "Display errors ativo" "OK"

}

# Detectar vulnerabilidades
detect_vulns

# Finalizar HTML
{
echo "</table>"
echo "<p>Relatório gerado automaticamente em $(date)</p>"
echo "</body>"
echo "</html>"
} >> "$OUTPUT"

echo "✅ Relatório HTML gerado: $OUTPUT"
