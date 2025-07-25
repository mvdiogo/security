#!/bin/bash
# Script de diagnóstico e correção para PyShark

echo "🔧 DIAGNÓSTICO PYSHARK - Verificando dependências..."
echo "=================================================="

# 1. Verificar se tshark/dumpcap estão instalados
echo "📦 Verificando instalação do Wireshark/tshark..."
if command -v tshark &> /dev/null; then
    echo "✅ tshark encontrado: $(which tshark)"
    tshark --version | head -1
else
    echo "❌ tshark não encontrado!"
    echo "💡 Instalando tshark..."
    
    # Detectar distribuição e instalar
    if [ -f /etc/debian_version ]; then
        echo "🐧 Detectado: Debian/Ubuntu"
        sudo apt-get update
        sudo apt-get install -y tshark wireshark-common
    elif [ -f /etc/redhat-release ]; then
        echo "🎩 Detectado: Red Hat/CentOS/Fedora"
        sudo yum install -y wireshark
        # ou para sistemas mais novos: sudo dnf install wireshark
    elif [ -f /etc/arch-release ]; then
        echo "🏹 Detectado: Arch Linux"
        sudo pacman -S wireshark-qt
    else
        echo "❓ Distribuição não detectada. Instale manualmente:"
        echo "   Ubuntu/Debian: sudo apt-get install tshark"
        echo "   CentOS/RHEL: sudo yum install wireshark"
        echo "   Fedora: sudo dnf install wireshark"
    fi
fi

echo ""

# 2. Verificar dumpcap
echo "🔍 Verificando dumpcap..."
if [ -f /usr/bin/dumpcap ]; then
    echo "✅ dumpcap encontrado: /usr/bin/dumpcap"
    ls -la /usr/bin/dumpcap
else
    echo "❌ dumpcap não encontrado em /usr/bin/"
    echo "🔍 Procurando dumpcap..."
    find /usr -name "dumpcap" 2>/dev/null || echo "   Não encontrado"
fi

echo ""

# 3. Verificar permissões
echo "🔐 Verificando permissões..."
if [ -f /usr/bin/dumpcap ]; then
    # Verificar se dumpcap tem capabilities ou está no grupo correto
    echo "📋 Capacidades atuais do dumpcap:"
    getcap /usr/bin/dumpcap 2>/dev/null || echo "   Nenhuma capability definida"
    
    echo "📋 Grupos do usuário atual:"
    groups
    
    echo "💡 Configurações recomendadas:"
    echo "   1. Adicionar capabilities ao dumpcap:"
    echo "      sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap"
    echo ""
    echo "   2. OU adicionar usuário ao grupo wireshark:"
    echo "      sudo usermod -a -G wireshark $USER"
    echo "      (depois faça logout/login)"
    echo ""
    echo "   3. OU sempre executar com sudo:"
    echo "      sudo python3 network_sniffer.py"
fi

echo ""

# 4. Verificar interfaces de rede
echo "🌐 Interfaces de rede disponíveis:"
ip link show 2>/dev/null | grep -E '^[0-9]+:' | cut -d':' -f2 | sed 's/^ */   • /'

echo ""

# 5. Teste rápido
# 5. Teste rápido
echo "🧪 Teste rápido de captura..."
echo "Tentando capturar 1 pacote ICMP (ping)..."

# Interface padrão
DEFAULT_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {print $5}' | head -1)
[ -z "$DEFAULT_IFACE" ] && DEFAULT_IFACE="any"

echo "🌐 Interface usada para teste: $DEFAULT_IFACE"

# Inicia ping no fundo
ping -c 3 8.8.8.8 > /dev/null 2>&1 &
PING_PID=$!

# Espera 1s para garantir tráfego
sleep 1

# Captura ICMP até encontrar 1 pacote (sem timeout)
if sudo tshark -i "$DEFAULT_IFACE" -f "icmp" -c 1 2>/dev/null; then
    echo "✅ Captura funcionando!"
else
    echo "❌ Captura falhou!"
fi

# Finaliza ping se ainda estiver rodando
kill $PING_PID 2>/dev/null

echo ""
echo "🎯 PRÓXIMOS PASSOS:"
echo "1. Execute: sudo python3 network_sniffer.py"
echo "2. Ou configure as permissões conforme sugerido acima"
echo "3. Use interface 'any' para capturar de todas as interfaces"
