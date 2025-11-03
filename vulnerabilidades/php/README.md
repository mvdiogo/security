Arquivos Criados:
1. vulnerable_app.php
Aplicação PHP com 7 vulnerabilidades reais implementadas:

✅ CVE-2025-6491 - SOAP XML Namespace Overflow
✅ CVE-2025-1861 - HTTP Redirect URL Truncation
✅ CVE-2025-1736 - HTTP Header Injection
✅ CVE-2025-1220 - Null Byte in Hostname
✅ CVE-2022-31631 - PDO SQLite Quote Overflow
✅ CVE-2025-1734 - Invalid HTTP Headers
✅ CVE-2025-1217 - Folded HTTP Headers

2. exploit_tests.sh
Script bash com testes curl para explorar cada vulnerabilidade
🚀 Como Usar:

# 1. Salvar os arquivos
# vulnerable_app.php e exploit_tests.sh

# 2. Iniciar o servidor PHP
php -S localhost:8000 vulnerable_app.php

# 3. Em outro terminal, executar os testes
chmod +x exploit_tests.sh
./exploit_tests.sh


O que cada teste faz:
CVE-2025-6491: Envia XML com namespace prefix gigante (10KB) para causar crash
CVE-2025-1861: Envia URL de 2000+ bytes que será truncada em 1024 bytes
CVE-2025-1736: Injeta headers maliciosos via caracteres CRLF (\r\n)
CVE-2025-1220: Usa null byte (\x00) para fazer bypass de validação de hostname
CVE-2022-31631: Envia string de 1MB para causar overflow no PDO::quote()
CVE-2025-1734: Envia header sem dois-pontos que é aceito como válido
CVE-2025-1217: Envia header "dobrado" (folded) que é parseado incorretamente
📊 Cada teste retorna:

✅ Status HTTP
🔍 Detecção da vulnerabilidade
📍 Local exato da falha (linha do código)
💥 Causa raiz do problema
⚠️ Impacto na segurança

⚠️ IMPORTANTE:
Este código é APENAS EDUCACIONAL. Use exclusivamente em ambientes de teste isolados. Nunca use em produção ou contra sistemas sem autorização expressa!