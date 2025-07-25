#!/bin/bash
# Script para detectar vulnerabilidades no sistema
# Desenvolvido para laboratório de segurança da informação

echo "🔍 Iniciando varredura de vulnerabilidades..."
echo "=================================================="

TARGET_IP=${1:-localhost}
REPORT_FILE="/tmp/vulnerability_report_$(date +%Y%m%d_%H%M%S).txt"

echo "Relatório de Vulnerabilidades - $(date)" > "$REPORT_FILE"
echo "Target: $TARGET_IP" >> "$REPORT_FILE"
echo "==================================================" >> "$REPORT_FILE"

# Função para testar portas
test_port() {
    local port=$1
    local service=$2
    echo -n "🔍 Testando $service (porta $port)... "
    if timeout 3 bash -c "echo >/dev/tcp/$TARGET_IP/$port" 2>/dev/null; then
        echo "✅ ABERTA"
        echo "[VULNERABILIDADE] Porta $port ($service) está aberta" >> "$REPORT_FILE"
        return 0
    else
        echo "❌ FECHADA"
        return 1
    fi
}

# Função para testar SSH
test_ssh() {
    echo "🔍 Testando vulnerabilidades SSH..."
    if test_port 22 "SSH" || test_port 2222 "SSH"; then
        echo "  - Testando login com credenciais fracas..."
        
        # Lista de credenciais comuns para testar
        declare -a credentials=(
            "root:root"
            "root:root123"
            "root:password"
            "root:123456"
            "admin:admin"
            "testuser:password123"
            "guest:guest"
        )
        
        for cred in "${credentials[@]}"; do
            user=$(echo $cred | cut -d: -f1)
            pass=$(echo $cred | cut -d: -f2)
            echo "    Testando $user:$pass..."
            
            sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
                $user@$TARGET_IP "echo 'SSH Login successful'" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "    ⚠️  CREDENCIAL FRACA ENCONTRADA: $user:$pass"
                echo "[CRÍTICO] SSH - Credencial fraca: $user:$pass" >> "$REPORT_FILE"
            fi
        done
    fi
}

# Função para testar FTP
test_ftp() {
    echo "🔍 Testando vulnerabilidades FTP..."
    if test_port 21 "FTP"; then
        echo "  - Testando login anônimo..."
        
        # Testar login anônimo
        if timeout 10 ftp -n $TARGET_IP <<EOF 2>/dev/null | grep -q "230"
user anonymous
pass anonymous
quit
EOF
        then
            echo "    ⚠️  LOGIN ANÔNIMO PERMITIDO"
            echo "[CRÍTICO] FTP - Login anônimo permitido" >> "$REPORT_FILE"
        fi
        
        # Testar credenciais fracas
        echo "  - Testando credenciais fracas..."
        declare -a ftp_creds=("ftp:ftp" "admin:admin" "test:test")
        for cred in "${ftp_creds[@]}"; do
            user=$(echo $cred | cut -d: -f1)
            pass=$(echo $cred | cut -d: -f2)
            if timeout 10 ftp -n $TARGET_IP <<EOF 2>/dev/null | grep -q "230"
user $user
pass $pass
quit
EOF
            then
                echo "    ⚠️  CREDENCIAL FRACA: $user:$pass"
                echo "[CRÍTICO] FTP - Credencial fraca: $user:$pass" >> "$REPORT_FILE"
            fi
        done
    fi
}

# Função para testar HTTP
test_http() {
    echo "🔍 Testando vulnerabilidades HTTP..."
    local http_port=80
    if [ "$TARGET_IP" = "localhost" ]; then
        http_port=8080
    fi
    
    if test_port $http_port "HTTP"; then
        echo "  - Verificando páginas sensíveis..."
        
        # Lista de páginas/diretórios sensíveis
        declare -a sensitive_pages=(
            "info.php"
            "phpinfo.php"
            "login.php"
            "upload.php"
            "admin"
            "backup"
            "config"
            "test"
        )
        
        for page in "${sensitive_pages[@]}"; do
            response=$(curl -s -o /dev/null -w "%{http_code}" http://$TARGET_IP:$http_port/$page 2>/dev/null)
            if [ "$response" = "200" ]; then
                echo "    ⚠️  PÁGINA SENSÍVEL ACESSÍVEL: /$page"
                echo "[ALTO] HTTP - Página sensível acessível: /$page" >> "$REPORT_FILE"
            fi
        done
        
        # Testar directory listing
        response=$(curl -s http://$TARGET_IP:$http_port/ 2>/dev/null | grep -i "index of")
        if [ $? -eq 0 ]; then
            echo "    ⚠️  DIRECTORY LISTING HABILITADO"
            echo "[MÉDIO] HTTP - Directory listing habilitado" >> "$REPORT_FILE"
        fi
    fi
}

# Função para testar bases de dados
test_databases() {
    echo "🔍 Testando vulnerabilidades em bases de dados..."
    
    # MySQL/MariaDB
    if test_port 3306 "MySQL"; then
        echo "  - Testando MySQL sem senha..."
        if mysql -h $TARGET_IP -u root -e "SELECT 1;" 2>/dev/null; then
            echo "    ⚠️  MYSQL SEM SENHA PARA ROOT"
            echo "[CRÍTICO] MySQL - Root sem senha" >> "$REPORT_FILE"
        fi
    fi
    
    # PostgreSQL
    if test_port 5432 "PostgreSQL"; then
        echo "  - Testando PostgreSQL com autenticação trust..."
        if PGPASSWORD="" psql -h $TARGET_IP -U postgres -c "SELECT 1;" 2>/dev/null; then
            echo "    ⚠️  POSTGRESQL COM AUTENTICAÇÃO TRUST"
            echo "[CRÍTICO] PostgreSQL - Autenticação trust habilitada" >> "$REPORT_FILE"
        fi
    fi
    
    # Redis
    if test_port 6379 "Redis"; then
        echo "  - Testando Redis sem autenticação..."
        if echo "INFO" | redis-cli -h $TARGET_IP 2>/dev/null | grep -q "redis_version"; then
            echo "    ⚠️  REDIS SEM AUTENTICAÇÃO"
            echo "[CRÍTICO] Redis - Sem autenticação" >> "$REPORT_FILE"
        fi
    fi
}

# Função para testar SNMP
test_snmp() {
    echo "🔍 Testando vulnerabilidades SNMP..."
    if test_port 161 "SNMP"; then
        echo "  - Testando community strings fracas..."
        
        declare -a communities=("public" "private" "community" "read" "write")
        for community in "${communities[@]}"; do
            if snmpwalk -v2c -c $community $TARGET_IP 1.3.6.1.2.1.1.1.0 2>/dev/null | grep -q "SNMPv2-MIB"; then
                echo "    ⚠️  COMMUNITY STRING FRACA: $community"
                echo "[ALTO] SNMP - Community string fraca: $community" >> "$REPORT_FILE"
            fi
        done
    fi
}

# Função para testar Samba/SMB
test_samba() {
    echo "🔍 Testando vulnerabilidades Samba/SMB..."
    if test_port 139 "SMB" || test_port 445 "SMB"; then
        echo "  - Verificando compartilhamentos..."
        
        # Listar compartilhamentos
        shares=$(smbclient -L $TARGET_IP -N 2>/dev/null | grep "Disk" | awk '{print $1}')
        if [ ! -z "$shares" ]; then
            echo "    📁 Compartilhamentos encontrados:"
            echo "$shares" | while read share; do
                echo "      - $share"
                echo "[MÉDIO] SMB - Compartilhamento encontrado: $share" >> "$REPORT_FILE"
                
                # Testar acesso anônimo
                if smbclient //$TARGET_IP/$share -N -c "ls" 2>/dev/null | grep -q "blocks available"; then
                    echo "        ⚠️  ACESSO ANÔNIMO PERMITIDO"
                    echo "[ALTO] SMB - Acesso anônimo ao compartilhamento: $share" >> "$REPORT_FILE"
                fi
            done
        fi
    fi
}

# Função para testar NFS
test_nfs() {
    echo "🔍 Testando vulnerabilidades NFS..."
    if test_port 111 "RPC" && test_port 2049 "NFS"; then
        echo "  - Verificando exportações NFS..."
        
        exports=$(showmount -e $TARGET_IP 2>/dev/null | grep -v "Export list")
        if [ ! -z "$exports" ]; then
            echo "    📁 Exportações NFS encontradas:"
            echo "$exports" | while read export; do
                export_path=$(echo $export | awk '{print $1}')
                export_hosts=$(echo $export | awk '{print $2}')
                echo "      - $export_path ($export_hosts)"
                echo "[MÉDIO] NFS - Exportação encontrada: $export_path para $export_hosts" >> "$REPORT_FILE"
                
                if echo $export_hosts | grep -q "\*"; then
                    echo "        ⚠️  EXPORTAÇÃO PARA TODOS OS HOSTS (*)"
                    echo "[ALTO] NFS - Exportação insegura para todos os hosts: $export_path" >> "$REPORT_FILE"
                fi
            done
        fi
    fi
}

# Função para testar Telnet
test_telnet() {
    echo "🔍 Testando vulnerabilidades Telnet..."
    if test_port 23 "Telnet"; then
        echo "    ⚠️  TELNET ESTÁ ATIVO"
        echo "[ALTO] Telnet - Serviço inseguro ativo" >> "$REPORT_FILE"
        
        # Testar credenciais fracas via telnet é mais complexo
        # devido à natureza interativa do protocolo
        echo "  - ⚠️  Protocolo inseguro - credenciais transmitidas em texto claro"
    fi
}

# Função para scan de portas com nmap
nmap_scan() {
    echo "🔍 Executando scan de portas com nmap..."
    if command -v nmap >/dev/null 2>&1; then
        nmap_result=$(nmap -sS -O -sV --script vuln $TARGET_IP 2>/dev/null)
        echo "$nmap_result" >> "$REPORT_FILE"
        
        # Verificar portas abertas
        open_ports=$(echo "$nmap_result" | grep "^[0-9]" | grep "open")
        if [ ! -z "$open_ports" ]; then
            echo "  📊 Resumo de portas abertas:"
            echo "$open_ports" | while read line; do
                port=$(echo $line | awk '{print $1}')
                service=$(echo $line | awk '{print $3}')
                echo "    - $port ($service)"
            done
        fi
    else
        echo "  ❌ nmap não disponível"
    fi
}

# Função principal de teste
run_vulnerability_tests() {
    echo "🎯 Alvo: $TARGET_IP"
    echo ""
    
    # Executar todos os testes
    test_ssh
    echo ""
    test_ftp
    echo ""
    test_http
    echo ""
    test_databases
    echo ""
    test_snmp
    echo ""
    test_samba
    echo ""
    test_nfs
    echo ""
    test_telnet
    echo ""
    nmap_scan
}

# Função para gerar resumo
generate_summary() {
    echo "" >> "$REPORT_FILE"
    echo "RESUMO DE VULNERABILIDADES" >> "$REPORT_FILE"
    echo "=========================" >> "$REPORT_FILE"
    
    critical=$(grep -c "\[CRÍTICO\]" "$REPORT_FILE" 2>/dev/null || echo "0")
    high=$(grep -c "\[ALTO\]" "$REPORT_FILE" 2>/dev/null || echo "0")
    medium=$(grep -c "\[MÉDIO\]" "$REPORT_FILE" 2>/dev/null || echo "0")
    
    echo "Vulnerabilidades Críticas: $critical" >> "$REPORT_FILE"
    echo "Vulnerabilidades Altas: $high" >> "$REPORT_FILE"
    echo "Vulnerabilidades Médias: $medium" >> "$REPORT_FILE"
    echo "Total: $((critical + high + medium))" >> "$REPORT_FILE"
    
    echo ""
    echo "📊 RESUMO FINAL:"
    echo "   🔴 Críticas: $critical"
    echo "   🟡 Altas: $high"
    echo "   🟢 Médias: $medium"
    echo "   📄 Relatório salvo em: $REPORT_FILE"
}

# Executar testes
echo "⚠️  AVISO: Este script deve ser usado apenas em ambientes de laboratório!"
echo "========================================================================="
echo ""

run_vulnerability_tests
echo ""
echo "=================================================="
generate_summary

echo ""
echo "✅ Varredura concluída!"
echo "📁 Relatório detalhado disponível em: $REPORT_FILE"