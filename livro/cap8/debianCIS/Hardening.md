# Implementação Prática CIS Benchmark - Debian 12

## Visão Geral
Este guia implementa os controles de segurança mais críticos do CIS Benchmark para Debian 12, focando em hardening do sistema operacional e configurações de segurança essenciais.

## 1. Preparação do Ambiente

### 1.1 Backup do Sistema
```bash
#!/bin/bash
# Script de backup antes da implementação
echo "=== Backup de Configurações Críticas ==="
mkdir -p /backup/cis-implementation/$(date +%Y%m%d)
BACKUP_DIR="/backup/cis-implementation/$(date +%Y%m%d)"

# Backup de arquivos importantes
cp /etc/passwd $BACKUP_DIR/
cp /etc/shadow $BACKUP_DIR/
cp /etc/group $BACKUP_DIR/
cp /etc/sudoers $BACKUP_DIR/
cp -r /etc/ssh/ $BACKUP_DIR/ssh/
cp /etc/login.defs $BACKUP_DIR/
cp /etc/pam.d/ $BACKUP_DIR/pam.d/ -r

echo "Backup concluído em: $BACKUP_DIR"
```

### 1.2 Script de Auditoria Inicial
```bash
#!/bin/bash
# cis_audit.sh - Script de auditoria CIS para Debian 12

echo "=== AUDITORIA CIS BENCHMARK DEBIAN 12 ==="
echo "Data: $(date)"
echo "=========================================="

# 1.1.1 Verificar se cramfs está desabilitado
echo "[1.1.1] Verificando cramfs..."
if lsmod | grep -q cramfs; then
    echo "FALHA: cramfs está carregado"
else
    echo "OK: cramfs não está carregado"
fi

# 1.1.2 Verificar se freevxfs está desabilitado
echo "[1.1.2] Verificando freevxfs..."
if lsmod | grep -q freevxfs; then
    echo "FALHA: freevxfs está carregado"
else
    echo "OK: freevxfs não está carregado"
fi

# 2.1.1 Verificar se xinetd está instalado
echo "[2.1.1] Verificando xinetd..."
if dpkg -l | grep -q xinetd; then
    echo "FALHA: xinetd está instalado"
else
    echo "OK: xinetd não está instalado"
fi

# 3.1.1 Verificar IP forwarding
echo "[3.1.1] Verificando IP forwarding..."
if sysctl net.ipv4.ip_forward | grep -q "= 1"; then
    echo "FALHA: IP forwarding está habilitado"
else
    echo "OK: IP forwarding está desabilitado"
fi

# 4.1.1 Verificar auditd
echo "[4.1.1] Verificando auditd..."
if systemctl is-enabled auditd | grep -q enabled; then
    echo "OK: auditd está habilitado"
else
    echo "FALHA: auditd não está habilitado"
fi

# 5.1.1 Verificar cron
echo "[5.1.1] Verificando cron..."
if systemctl is-enabled cron | grep -q enabled; then
    echo "OK: cron está habilitado"
else
    echo "FALHA: cron não está habilitado"
fi
```

## 2. Implementação de Controles Críticos

### 2.1 Desabilitar Sistemas de Arquivos Desnecessários
```bash
#!/bin/bash
# disable_filesystems.sh

echo "=== Desabilitando sistemas de arquivos desnecessários ==="

# Criar arquivo de configuração para blacklist
cat > /etc/modprobe.d/cis-blacklist.conf << 'EOF'
# CIS Benchmark - Sistemas de arquivos desnecessários
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install fat /bin/true
install vfat /bin/true
EOF

echo "Sistemas de arquivos blacklistados configurados"

# Remover módulos se já carregados
for module in cramfs freevxfs jffs2 hfs hfsplus squashfs udf fat vfat; do
    if lsmod | grep -q "^$module "; then
        echo "Removendo módulo: $module"
        rmmod $module 2>/dev/null || echo "Aviso: Não foi possível remover $module"
    fi
done
```

### 2.2 Configuração de Rede Segura
```bash
#!/bin/bash
# network_hardening.sh

echo "=== Configurando parâmetros de rede seguros ==="

# Criar arquivo de configuração sysctl para CIS
cat > /etc/sysctl.d/99-cis.conf << 'EOF'
# CIS Benchmark Network Configuration

# 3.1.1 Desabilitar IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 3.1.2 Desabilitar packet redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 3.2.1 Não aceitar source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# 3.2.2 Não aceitar ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 3.2.3 Não aceitar secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# 3.2.4 Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 3.2.5 Ignorar broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 3.2.6 Ignorar bogus ICMP responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 3.2.7 Reverse Path Filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 3.2.8 TCP SYN Cookies
net.ipv4.tcp_syncookies = 1

# 3.3.1 Desabilitar IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# 3.3.2 Não aceitar IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF

# Aplicar configurações
sysctl -p /etc/sysctl.d/99-cis.conf
echo "Configurações de rede aplicadas"
```

### 2.3 Configuração do SSH
```bash
#!/bin/bash
# ssh_hardening.sh

echo "=== Configurando SSH de forma segura ==="

# Backup da configuração original
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

# Criar nova configuração SSH baseada no CIS
cat > /etc/ssh/sshd_config << 'EOF'
# CIS Benchmark SSH Configuration for Debian 12

# 5.2.1 Configurações básicas
Port 22
Protocol 2
AddressFamily inet

# 5.2.2 Configurações de logging
SyslogFacility AUTHPRIV
LogLevel INFO

# 5.2.3 Permissões de acesso
PermitRootLogin no
MaxAuthTries 4
MaxSessions 4
MaxStartups 10:30:60

# 5.2.4 Configurações de criptografia
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# 5.2.5 Configurações de autenticação
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no

# 5.2.6 Configurações de tempo
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60

# 5.2.7 Outras configurações de segurança
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
Compression no
AllowAgentForwarding no
AllowStreamLocalForwarding no
GatewayPorts no

# 5.2.8 Banner
Banner /etc/issue.net

# 5.2.9 Configurar usuários permitidos (ajustar conforme necessário)
# AllowUsers admin
# AllowGroups ssh-users
EOF

# Criar banner de segurança
cat > /etc/issue.net << 'EOF'
***************************************************************************
                            AVISO DE SEGURANÇA
                            
Este sistema é para uso autorizado apenas. Todas as atividades podem ser
monitoradas e registradas. O uso não autorizado é proibido e pode resultar
em processo criminal e/ou civil.
***************************************************************************
EOF

# Definir permissões corretas
chmod 644 /etc/ssh/sshd_config
chmod 644 /etc/issue.net

# Validar e reiniciar SSH
if sshd -t; then
    echo "Configuração SSH válida"
    systemctl reload sshd
    echo "SSH recarregado com novas configurações"
else
    echo "ERRO: Configuração SSH inválida. Restaurando backup..."
    cp /etc/ssh/sshd_config.backup.$(date +%Y%m%d) /etc/ssh/sshd_config
fi
```

### 2.4 Configuração de Auditoria (auditd)
```bash
#!/bin/bash
# audit_configuration.sh

echo "=== Configurando auditoria do sistema ==="

# Instalar auditd se não estiver instalado
if ! dpkg -l | grep -q auditd; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Backup da configuração original
cp /etc/audit/auditd.conf /etc/audit/auditd.conf.backup.$(date +%Y%m%d)
cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.backup.$(date +%Y%m%d) 2>/dev/null || true

# Configurar auditd.conf
cat > /etc/audit/auditd.conf << 'EOF'
# CIS Benchmark Audit Configuration

# 4.1.1.1 Configurações básicas
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = adm
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE

# 4.1.1.2 Configurações de espaço
max_log_file = 32
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND

# 4.1.1.3 Configurações de rede
tcp_listen_port = 
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
EOF

# Criar regras de auditoria CIS
cat > /etc/audit/rules.d/cis.rules << 'EOF'
# CIS Benchmark Audit Rules for Debian 12

# 4.1.3 Ensure events that modify date and time information are collected
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# 4.1.4 Ensure events that modify user/group information are collected
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# 4.1.5 Ensure events that modify the system's network environment are collected
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale

# 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# 4.1.7 Ensure login and logout events are collected
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# 4.1.8 Ensure session initiation information is collected
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# 4.1.9 Ensure discretionary access control permission modification events are collected
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# 4.1.11 Ensure use of privileged commands is collected
# This will be populated with find command results for SUID/SGID files

# 4.1.12 Ensure successful file system mounts are collected
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# 4.1.13 Ensure file deletion events by users are collected
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# 4.1.14 Ensure changes to system administration scope (sudoers) is collected
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# 4.1.15 Ensure system administrator actions (sudolog) are collected
-w /var/log/sudo.log -p wa -k actions

# 4.1.16 Ensure kernel module loading and unloading is collected
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# 4.1.17 Ensure the audit configuration is immutable
-e 2
EOF

# Encontrar arquivos SUID/SGID e adicionar às regras
echo "# 4.1.11 Privileged commands" >> /etc/audit/rules.d/cis.rules
find /usr/bin /usr/sbin /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read file; do
    echo "-w $file -p x -k privileged" >> /etc/audit/rules.d/cis.rules
done

# Habilitar e iniciar auditd
systemctl enable auditd
systemctl start auditd

# Aplicar novas regras
augenrules --load
systemctl restart auditd

echo "Configuração de auditoria concluída"
```

### 2.5 Configuração de Logs
```bash
#!/bin/bash
# logging_configuration.sh

echo "=== Configurando sistema de logs ==="

# Instalar rsyslog se não estiver instalado
if ! dpkg -l | grep -q rsyslog; then
    apt-get update
    apt-get install -y rsyslog
fi

# Backup da configuração original
cp /etc/rsyslog.conf /etc/rsyslog.conf.backup.$(date +%Y%m%d)

# Configurar rsyslog para CIS
cat > /etc/rsyslog.d/50-cis.conf << 'EOF'
# CIS Benchmark Logging Configuration

# 4.2.1.1 Ensure rsyslog is configured to send logs to a remote log host
# Uncomment and configure for remote logging if needed
# *.* @@logserver.example.com:514

# 4.2.1.3 Ensure logging is configured
*.emerg                                                 :omusrmsg:*
mail.*                                                  -/var/log/mail
mail.info                                               -/var/log/mail.info
mail.warning                                            -/var/log/mail.warn
mail.err                                                /var/log/mail.err
news.crit                                               -/var/log/news/news.crit
news.err                                                -/var/log/news/news.err
news.notice                                             -/var/log/news/news.notice
*.=warning;*.=err                                       -/var/log/warn
*.crit                                                  /var/log/warn
*.*;mail.none;news.none                                 -/var/log/messages
local0,local1.*                                         -/var/log/localmessages
local2,local3.*                                         -/var/log/localmessages
local4,local5.*                                         -/var/log/localmessages
local6,local7.*                                         -/var/log/localmessages

# Authentication logs
auth,authpriv.*                                         /var/log/auth.log

# Kernel logs
kern.*                                                  -/var/log/kern.log

# System logs
daemon.*                                                -/var/log/daemon.log
syslog.*                                                -/var/log/syslog
lpr.*                                                   -/var/log/lpr.log
user.*                                                  -/var/log/user.log
uucp.*                                                  -/var/log/uucp.log

# Debug logs
*.=debug                                                -/var/log/debug
*.=info;*.=notice;*.=warning;*.!=err                   -/var/log/messages
*.=err                                                  /var/log/error
*.crit                                                  /var/log/critical
EOF

# Configurar logrotate para os logs CIS
cat > /etc/logrotate.d/cis-logs << 'EOF'
# CIS Benchmark Log Rotation

/var/log/warn
/var/log/messages
/var/log/localmessages
/var/log/critical
/var/log/error {
    weekly
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 syslog adm
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

# Configurar permissões dos arquivos de log
mkdir -p /var/log/news
touch /var/log/{warn,messages,localmessages,critical,error}
touch /var/log/news/{news.crit,news.err,news.notice}

chown syslog:adm /var/log/{warn,messages,localmessages,critical,error}
chown syslog:adm /var/log/news/{news.crit,news.err,news.notice}
chmod 640 /var/log/{warn,messages,localmessages,critical,error}
chmod 640 /var/log/news/{news.crit,news.err,news.notice}

# Reiniciar rsyslog
systemctl restart rsyslog
systemctl enable rsyslog

echo "Configuração de logging concluída"
```

### 2.6 Configuração de Firewall
```bash
#!/bin/bash
# firewall_configuration.sh

echo "=== Configurando firewall com ufw ==="

# Instalar ufw se não estiver instalado
if ! dpkg -l | grep -q ufw; then
    apt-get update
    apt-get install -y ufw
fi

# Reset do ufw para começar limpo
ufw --force reset

# Configurações padrão CIS
ufw default deny incoming
ufw default deny outgoing
ufw default deny forward

# Permitir conexões essenciais de saída
ufw allow out 53    # DNS
ufw allow out 80    # HTTP
ufw allow out 443   # HTTPS
ufw allow out 123   # NTP

# Permitir SSH (ajustar porta se necessário)
ufw allow in 22/tcp

# Permitir loopback
ufw allow in on lo
ufw allow out on lo

# Configurar logging
ufw logging on

# Habilitar firewall
ufw --force enable

# Verificar status
ufw status verbose

echo "Firewall configurado e habilitado"
```

## 3. Scripts de Validação

### 3.1 Script de Validação Completa
```bash
#!/bin/bash
# cis_validation.sh - Validação completa dos controles CIS

echo "=== VALIDAÇÃO CIS BENCHMARK DEBIAN 12 ==="
echo "Data: $(date)"
echo "============================================"

PASS=0
FAIL=0

check_result() {
    if [ $1 -eq 0 ]; then
        echo "✓ PASS: $2"
        ((PASS++))
    else
        echo "✗ FAIL: $2"
        ((FAIL++))
    fi
}

# Verificar sistemas de arquivos
echo -e "\n[1] VERIFICAÇÕES DE SISTEMA DE ARQUIVOS"
lsmod | grep -q cramfs
check_result $? "cramfs não está carregado"

lsmod | grep -q freevxfs
check_result $? "freevxfs não está carregado"

# Verificar configurações de rede
echo -e "\n[2] VERIFICAÇÕES DE REDE"
sysctl net.ipv4.ip_forward | grep -q "= 0"
check_result $? "IP forwarding desabilitado"

sysctl net.ipv4.conf.all.send_redirects | grep -q "= 0"
check_result $? "Send redirects desabilitado"

sysctl net.ipv4.conf.all.accept_source_route | grep -q "= 0"
check_result $? "Accept source route desabilitado"

# Verificar SSH
echo -e "\n[3] VERIFICAÇÕES SSH"
grep -q "^PermitRootLogin no" /etc/ssh/sshd_config
check_result $? "Root login desabilitado no SSH"

grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config
check_result $? "Autenticação por senha desabilitada no SSH"

grep -q "^MaxAuthTries 4" /etc/ssh/sshd_config
check_result $? "MaxAuthTries configurado corretamente no SSH"

# Verificar auditoria
echo -e "\n[4] VERIFICAÇÕES DE AUDITORIA"
systemctl is-enabled auditd | grep -q enabled
check_result $? "auditd está habilitado"

test -f /etc/audit/rules.d/cis.rules
check_result $? "Regras CIS de auditoria configuradas"

# Verificar logs
echo -e "\n[5] VERIFICAÇÕES DE LOGGING"
systemctl is-enabled rsyslog | grep -q enabled
check_result $? "rsyslog está habilitado"

test -f /etc/rsyslog.d/50-cis.conf
check_result $? "Configuração CIS de logging aplicada"

# Verificar firewall
echo -e "\n[6] VERIFICAÇÕES DE FIREWALL"
ufw status | grep -q "Status: active"
check_result $? "Firewall UFW está ativo"

# Relatório Final
echo -e "\n============================================"
echo "RELATÓRIO FINAL:"
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "TOTAL: $((PASS + FAIL))"
echo "PERCENTUAL DE CONFORMIDADE: $(( PASS * 100 / (PASS + FAIL) ))%"
echo "============================================"

if [ $FAIL -eq 0 ]; then
    echo "✓ SISTEMA TOTALMENTE CONFORME COM CIS BENCHMARK"
    exit 0
else
    echo "⚠ SISTEMA PARCIALMENTE CONFORME - REVISAR ITENS FALHADOS"
    exit 1
fi
```

## 4. Implementação Automatizada

### 4.1 Script Master de Implementação
```bash
#!/bin/bash
# cis_master_implementation.sh - Script principal de implementação

set -e  # Parar em caso de erro

LOGFILE="/var/log/cis-implementation-$(date +%Y%m%d-%H%M%S).log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOGFILE"
}

log_message "=== INICIANDO IMPLEMENTAÇÃO CIS BENCHMARK DEBIAN 12 ==="

# Verificar se está rodando como root
if [ "$EUID" -ne 0 ]; then
    echo "Este script deve ser executado como root"
    exit 1
fi

# Verificar versão do Debian
if ! grep -q "VERSION_ID=\"12\"" /etc/os-release; then
    echo "Este script é específico para Debian 12"
    exit 1
fi

# Criar diretórios necessários
mkdir -p /opt/cis-scripts
mkdir -p /backup/cis-implementation

# Executar scripts em sequência
log_message "Executando backup do sistema..."
bash /opt/cis-scripts/backup.sh 2>&1 | tee -a "$LOGFILE"

log_message "Desabilitando sistemas de arquivos desnecessários..."
bash /opt/cis-scripts/disable_filesystems.sh 2>&1 | tee -a "$LOGFILE"

log_message "Configurando hardening de rede..."
bash /opt/cis-scripts/network_hardening.sh 2>&1 | tee -a "$LOGFILE"

log_message "Configurando SSH..."
bash /opt/cis-scripts/ssh_hardening.sh 2>&1 | tee -a "$LOGFILE"

log_message "Configurando auditoria..."
bash /opt/cis-scripts/audit_configuration.sh 2>&1 | tee -a "$LOGFILE"

log_message "Configurando logging..."
bash /opt/cis-scripts/logging_configuration.sh 2>&1 | tee -a "$LOGFILE"

log_message "Configurando firewall..."
bash /opt/cis-scripts/firewall_configuration.sh 2>&1 | tee -a "$LOGFILE"

log_message "Executando validação final..."
bash /opt/cis-scripts/cis_validation.sh 2>&1 | tee -a "$LOGFILE"

log_message "=== IMPLEMENTAÇÃO CIS BENCHMARK CONCLUÍDA ==="
log_message "Log completo disponível em: $LOGFILE"

echo ""
echo "PRÓXIMOS PASSOS:"
echo "1. Reiniciar o sistema para garantir que todas as configurações sejam aplicadas"
echo "2. Testar conectividade SSH antes de desconectar"
echo "3. Configurar usuários e grupos conforme necessário"
echo "4. Implementar controles adicionais específicos do ambiente"
echo "5. Configurar monitoramento dos logs de auditoria"
```

## 5. Configurações Adicionais de Segurança

### 5.1 Configuração de PAM (Pluggable Authentication Modules)
```bash
#!/bin/bash
# pam_configuration.sh

echo "=== Configurando PAM para CIS Benchmark ==="

# Backup das configurações PAM
cp /etc/pam.d/common-password /etc/pam.d/common-password.backup.$(date +%Y%m%d)
cp /etc/pam.d/common-auth /etc/pam.d/common-auth.backup.$(date +%Y%m%d)
cp /etc/login.defs /etc/login.defs.backup.$(date +%Y%m%d)

# 5.3.1 Configurar política de senhas
cat > /etc/pam.d/common-password << 'EOF'
# CIS Benchmark PAM Password Configuration
password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass sha512 remember=5
password requisite pam_deny.so
password required pam_permit.so
EOF

# 5.3.2 Configurar bloqueio de conta
cat > /etc/pam.d/common-auth << 'EOF'
# CIS Benchmark PAM Auth Configuration
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
auth [success=1 default=ignore] pam_unix.so nullok_secure
auth requisite pam_deny.so
auth required pam_permit.so
auth optional pam_cap.so
EOF

# Instalar libpam-pwquality se não estiver instalado
if ! dpkg -l | grep -q libpam-pwquality; then
    apt-get update
    apt-get install -y libpam-pwquality
fi

# 5.4.1 Configurar parâmetros de senha em login.defs
cat > /etc/login.defs << 'EOF'
# CIS Benchmark Login Definitions

# Password aging controls
PASS_MAX_DAYS   365
PASS_MIN_DAYS   1
PASS_WARN_AGE   7

# User and group creation defaults
UID_MIN         1000
UID_MAX         60000
GID_MIN         1000
GID_MAX         60000
CREATE_HOME     yes
UMASK           077

# Password encryption method
ENCRYPT_METHOD SHA512

# Login controls
LOGIN_RETRIES   5
LOGIN_TIMEOUT   60
FAILLOG_ENAB    yes
LASTLOG_ENAB    yes

# SU configuration
SU_NAME         su
SU_WHEEL_ONLY   no

# Console settings
CONSOLE_GROUPS  floppy:audio:cdrom

# Environment
ENV_SUPATH      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH        PATH=/usr/local/bin:/usr/bin:/bin

# Home directory permissions
HOME_MODE       0750

# User deletion
USERGROUPS_ENAB yes
USERDEL_CMD     /usr/sbin/userdel_local
EOF

echo "Configuração PAM concluída"
```

### 5.2 Configuração de Permissões de Arquivos Críticos
```bash
#!/bin/bash
# file_permissions.sh

echo "=== Configurando permissões de arquivos críticos ==="

# 6.1.2 Ensure permissions on /etc/passwd are configured
chown root:root /etc/passwd
chmod 644 /etc/passwd

# 6.1.3 Ensure permissions on /etc/shadow are configured
chown root:shadow /etc/shadow
chmod 640 /etc/shadow

# 6.1.4 Ensure permissions on /etc/group are configured
chown root:root /etc/group
chmod 644 /etc/group

# 6.1.5 Ensure permissions on /etc/gshadow are configured
chown root:shadow /etc/gshadow
chmod 640 /etc/gshadow

# 6.1.6 Ensure permissions on /etc/passwd- are configured
if [ -f /etc/passwd- ]; then
    chown root:root /etc/passwd-
    chmod 644 /etc/passwd-
fi

# 6.1.7 Ensure permissions on /etc/shadow- are configured
if [ -f /etc/shadow- ]; then
    chown root:shadow /etc/shadow-
    chmod 640 /etc/shadow-
fi

# 6.1.8 Ensure permissions on /etc/group- are configured
if [ -f /etc/group- ]; then
    chown root:root /etc/group-
    chmod 644 /etc/group-
fi

# 6.1.9 Ensure permissions on /etc/gshadow- are configured
if [ -f /etc/gshadow- ]; then
    chown root:shadow /etc/gshadow-
    chmod 640 /etc/gshadow-
fi

# SSH key permissions
if [ -d /etc/ssh ]; then
    chown -R root:root /etc/ssh
    chmod 755 /etc/ssh
    find /etc/ssh -name "ssh_host_*_key" -type f -exec chmod 600 {} \;
    find /etc/ssh -name "ssh_host_*_key.pub" -type f -exec chmod 644 {} \;
fi

# Crontab permissions
chown root:root /etc/crontab
chmod 600 /etc/crontab

# Log file permissions
if [ -d /var/log ]; then
    find /var/log -type f -exec chmod 640 {} \;
    find /var/log -type d -exec chmod 755 {} \;
fi

echo "Permissões de arquivos configuradas"
```

### 5.3 Configuração de Serviços Desnecessários
```bash
#!/bin/bash
# disable_services.sh

echo "=== Desabilitando serviços desnecessários ==="

# Lista de serviços a serem desabilitados conforme CIS
SERVICES_TO_DISABLE=(
    "avahi-daemon"
    "cups"
    "dhcpcd5"
    "isc-dhcp-server"
    "isc-dhcp-server6"
    "rpcbind"
    "rsync"
    "snmpd"
    "ypserv"
    "ypbind"
    "telnet"
    "rsh-server"
    "rlogin"
    "vsftpd"
    "apache2"
    "nginx"
    "bind9"
    "dnsmasq"
    "samba"
    "squid"
    "nfs-server"
    "nis"
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$service" >/dev/null 2>&1; then
        echo "Desabilitando serviço: $service"
        systemctl disable "$service"
        systemctl stop "$service"
    elif systemctl is-active "$service" >/dev/null 2>&1; then
        echo "Parando serviço: $service"
        systemctl stop "$service"
    fi
done

# Verificar e remover pacotes desnecessários se não estiverem sendo usados
PACKAGES_TO_REMOVE=(
    "telnet"
    "rsh-client"
    "rsh-redone-client"
    "talk"
    "ntalk"
    "ypbind"
    "yp-tools"
)

for package in "${PACKAGES_TO_REMOVE[@]}"; do
    if dpkg -l | grep -q "^ii.*$package "; then
        echo "Removendo pacote: $package"
        apt-get remove -y "$package"
    fi
done

echo "Serviços desnecessários desabilitados"
```

## 6. Monitoramento e Manutenção

### 6.1 Script de Monitoramento Contínuo
```bash
#!/bin/bash
# cis_monitor.sh - Script para monitoramento contínuo

ALERT_EMAIL="admin@example.com"  # Configurar email de alerta
LOG_FILE="/var/log/cis-monitor.log"

log_alert() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ALERT: $message" | tee -a "$LOG_FILE"
    
    # Enviar email se configurado
    if command -v mail >/dev/null 2>&1 && [ -n "$ALERT_EMAIL" ]; then
        echo "$message" | mail -s "CIS Alert - $(hostname)" "$ALERT_EMAIL"
    fi
}

# Verificar configurações críticas
check_ssh_config() {
    if ! grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
        log_alert "SSH: PermitRootLogin não está configurado como 'no'"
    fi
    
    if ! grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        log_alert "SSH: PasswordAuthentication não está desabilitado"
    fi
}

check_audit_service() {
    if ! systemctl is-active --quiet auditd; then
        log_alert "AUDIT: Serviço auditd não está rodando"
    fi
    
    if ! systemctl is-enabled --quiet auditd; then
        log_alert "AUDIT: Serviço auditd não está habilitado"
    fi
}

check_firewall() {
    if ! ufw status | grep -q "Status: active"; then
        log_alert "FIREWALL: UFW não está ativo"
    fi
}

check_failed_logins() {
    local failed_count=$(grep "authentication failure" /var/log/auth.log | wc -l)
    if [ "$failed_count" -gt 50 ]; then
        log_alert "SECURITY: $failed_count tentativas de login falharam nas últimas 24h"
    fi
}

check_system_integrity() {
    # Verificar mudanças em arquivos críticos
    local critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/sudoers"
        "/etc/ssh/sshd_config"
    )
    
    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            local current_hash=$(sha256sum "$file" | cut -d' ' -f1)
            local hash_file="/var/lib/cis-hashes/$(basename "$file").hash"
            
            if [ -f "$hash_file" ]; then
                local stored_hash=$(cat "$hash_file")
                if [ "$current_hash" != "$stored_hash" ]; then
                    log_alert "INTEGRITY: Arquivo $file foi modificado"
                    echo "$current_hash" > "$hash_file"
                fi
            else
                mkdir -p /var/lib/cis-hashes
                echo "$current_hash" > "$hash_file"
            fi
        fi
    done
}

# Executar verificações
echo "$(date '+%Y-%m-%d %H:%M:%S') Iniciando monitoramento CIS..." >> "$LOG_FILE"

check_ssh_config
check_audit_service
check_firewall
check_failed_logins
check_system_integrity

echo "$(date '+%Y-%m-%d %H:%M:%S') Monitoramento concluído" >> "$LOG_FILE"
```

### 6.2 Cron Job para Monitoramento Automático
```bash
#!/bin/bash
# setup_monitoring.sh

echo "=== Configurando monitoramento automático ==="

# Criar cron job para executar monitoramento a cada hora
cat > /etc/cron.d/cis-monitoring << 'EOF'
# CIS Benchmark Monitoring
0 * * * * root /opt/cis-scripts/cis_monitor.sh
# Audit report diário
0 6 * * * root /opt/cis-scripts/cis_validation.sh > /var/log/cis-daily-report-$(date +\%Y\%m\%d).log
EOF

# Configurar logrotate para logs de monitoramento
cat > /etc/logrotate.d/cis-monitoring << 'EOF'
/var/log/cis-monitor.log
/var/log/cis-daily-report-*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 root adm
}
EOF

# Criar diretório para hashes de integridade
mkdir -p /var/lib/cis-hashes
chmod 700 /var/lib/cis-hashes

echo "Monitoramento automático configurado"
```

## 7. Procedimentos de Manutenção

### 7.1 Script de Atualização Segura
```bash
#!/bin/bash
# secure_update.sh

echo "=== Procedimento de Atualização Segura CIS ==="

# Backup antes da atualização
echo "Criando backup pré-atualização..."
mkdir -p /backup/pre-update-$(date +%Y%m%d)
BACKUP_DIR="/backup/pre-update-$(date +%Y%m%d)"

# Backup de configurações críticas
cp -r /etc/ssh "$BACKUP_DIR/"
cp -r /etc/audit "$BACKUP_DIR/"
cp /etc/sysctl.d/99-cis.conf "$BACKUP_DIR/"
cp /etc/rsyslog.d/50-cis.conf "$BACKUP_DIR/"

# Executar validação pré-atualização
echo "Executando validação pré-atualização..."
/opt/cis-scripts/cis_validation.sh > "$BACKUP_DIR/pre-update-validation.log"

# Atualizar sistema
echo "Atualizando sistema..."
apt-get update
apt-get upgrade -y

# Executar validação pós-atualização
echo "Executando validação pós-atualização..."
/opt/cis-scripts/cis_validation.sh > "/var/log/post-update-validation-$(date +%Y%m%d).log"

# Verificar se serviços críticos estão rodando
echo "Verificando serviços críticos..."
services=("ssh" "auditd" "rsyslog" "ufw")
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "✓ $service está rodando"
    else
        echo "✗ $service NÃO está rodando - ATENÇÃO!"
        systemctl start "$service"
    fi
done

echo "Atualização concluída. Verifique os logs de validação."
```

## 8. Documentação e Relatórios

### 8.1 Gerador de Relatório de Conformidade
```bash
#!/bin/bash
# generate_compliance_report.sh

REPORT_FILE="/var/log/cis-compliance-report-$(date +%Y%m%d).html"

cat > "$REPORT_FILE" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>CIS Benchmark Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .section { margin: 20px 0; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>CIS Benchmark Compliance Report</h1>
        <p><strong>Sistema:</strong> $(hostname)</p>
        <p><strong>Data:</strong> $(date)</p>
        <p><strong>Versão:</strong> Debian 12</p>
    </div>
EOF

# Função para adicionar resultado ao relatório
add_check_result() {
    local check_id="$1"
    local description="$2"
    local command="$3"
    local result
    
    if eval "$command" >/dev/null 2>&1; then
        result='<span class="pass">PASS</span>'
    else
        result='<span class="fail">FAIL</span>'
    fi
    
    echo "<tr><td>$check_id</td><td>$description</td><td>$result</td></tr>" >> "$REPORT_FILE"
}

# Adicionar tabela de resultados
cat >> "$REPORT_FILE" << 'EOF'
    <div class="section">
        <h2>Resultados da Verificação</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Descrição</th>
                <th>Status</th>
            </tr>
EOF

# Executar verificações e adicionar ao relatório
add_check_result "1.1.1" "cramfs filesystem disabled" "! lsmod | grep -q cramfs"
add_check_result "1.1.2" "freevxfs filesystem disabled" "! lsmod | grep -q freevxfs"
add_check_result "3.1.1" "IP forwarding disabled" "sysctl net.ipv4.ip_forward | grep -q '= 0'"
add_check_result "3.2.1" "Source routed packets disabled" "sysctl net.ipv4.conf.all.accept_source_route | grep -q '= 0'"
add_check_result "4.1.1" "auditd enabled" "systemctl is-enabled auditd | grep -q enabled"
add_check_result "5.2.1" "SSH root login disabled" "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config"
add_check_result "5.2.2" "SSH password auth disabled" "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config"

# Finalizar relatório
cat >> "$REPORT_FILE" << 'EOF'
        </table>
    </div>
    
    <div class="section">
        <h2>Recomendações</h2>
        <ul>
            <li>Execute validações regulares usando o script cis_validation.sh</li>
            <li>Monitore logs de auditoria diariamente</li>
            <li>Mantenha o sistema atualizado com patches de segurança</li>
            <li>Revise configurações após mudanças no sistema</li>
        </ul>
    </div>
</body>
</html>
EOF

echo "Relatório gerado: $REPORT_FILE"
```

## 9. Instalação e Uso

### 9.1 Instruções de Instalação
```bash
# 1. Baixar e preparar scripts
mkdir -p /opt/cis-scripts
cd /opt/cis-scripts

# 2. Tornar scripts executáveis
chmod +x *.sh

# 3. Executar implementação completa
./cis_master_implementation.sh

# 4. Verificar implementação
./cis_validation.sh

# 5. Configurar monitoramento
./setup_monitoring.sh
```

### 9.2 Checklist de Verificação Pós-Implementação
- [ ] Sistema reiniciado após implementação
- [ ] SSH funciona corretamente com autenticação por chave
- [ ] Firewall está ativo e configurado
- [ ] Auditd está rodando e gerando logs
- [ ] Logs estão sendo rotacionados corretamente
- [ ] Monitoramento automático configurado
- [ ] Backup das configurações originais criado
- [ ] Documentação atualizada com mudanças específicas do ambiente

## 10. Considerações Importantes

### 10.1 Antes de Implementar
- **Sempre teste em ambiente de desenvolvimento primeiro**
- **Faça backup completo do sistema**
- **Tenha acesso console/físico disponível**
- **Documente configurações específicas do ambiente**

### 10.2 Manutenção Contínua
- Execute validações mensais
- Monitore logs de auditoria regularmente
- Mantenha o sistema atualizado
- Revise configurações após mudanças de infraestrutura
- Treine a equipe nas novas configurações

### 10.3 Customizações Necessárias
- Ajustar portas SSH se diferentes da padrão
- Configurar usuários e grupos específicos
- Adaptar regras de firewall para aplicações
- Configurar servidor de logs centralizado se disponível
- Ajustar políticas de senha conforme política organizacional

Este guia fornece uma base sólida para implementação do CIS Benchmark no Debian 12, mas deve ser adaptado às necessidades específicas de cada ambiente.