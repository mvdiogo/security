#!/usr/bin/env python3
"""
PyShark Network Analyzer Avançado
Versão educacional com detecção de IPs suspeitos, varreduras e geolocalização
"""

import pyshark
import sys
import platform
import subprocess
import requests
from collections import defaultdict
from datetime import datetime
from tabulate import tabulate
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)

# Função para verificar se interface é válida
def interface_existe(nome):
    try:
        interfaces = [i.name for i in pyshark.LiveCapture().interfaces]
        return nome in interfaces or nome == "any"
    except Exception:
        return True

# Função para entrada com valor padrão
def input_seguro(prompt, default, tipo=str):
    try:
        valor = input(prompt) or str(default)
        return tipo(valor)
    except ValueError:
        print(f"{Fore.RED}Valor inválido. Usando padrão: {default}{Style.RESET_ALL}")
        return default

# Listar interfaces

def mostrar_interfaces():
    print(f"{Fore.CYAN}Interfaces de Rede Disponíveis:{Style.RESET_ALL}")
    print("-" * 50)

    try:
        if platform.system() == "Linux":
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            print("Linux - Interfaces de Rede:")
            for line in result.stdout.split('\n'):
                if ': ' in line and 'state UP' in line:
                    interface = line.split(':')[1].strip().split('@')[0]
                    print(f"   • {interface}")

        elif platform.system() == "Windows":
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], capture_output=True, text=True)
            print("Windows - Interfaces de Rede:")
            for line in result.stdout.split('\n')[3:]:
                if line.strip() and 'Conectado' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        print(f"   • {' '.join(parts[3:])}")

        elif platform.system() == "Darwin":
            result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
            print("macOS - Interfaces de Rede:")
            for interface in result.stdout.strip().split():
                if not interface.startswith('lo'):
                    print(f"   • {interface}")

        interfaces = pyshark.LiveCapture().interfaces
        print(f"\n{Fore.YELLOW}Interfaces do Wireshark:{Style.RESET_ALL}")
        for i, interface in enumerate(interfaces, 1):
            print(f"{i}. {interface}")

    except Exception as e:
        print(f"{Fore.RED}Erro ao listar interfaces: {e}{Style.RESET_ALL}")

# Consulta IP externa

def consultar_ip(ip):
    try:
        print(f"\n Verificando IP: {ip}")
        url = f"https://ipapi.co/{ip}/json/"
        r = requests.get(url, timeout=5)
        data = r.json()
        print(f" Local: {data.get('city')}, {data.get('region')}, {data.get('country_name')}")
        print(f" ISP: {data.get('org')}")
    except Exception as e:
        print(f"{Fore.YELLOW}⚠️ Falha ao consultar IP: {e}{Style.RESET_ALL}")

# Analisar pacotes

def analisar_pacotes(interface='any', count=10):
    print(f"{Fore.GREEN} Capturando pacotes em {interface}...{Style.RESET_ALL}\n")

    dados = []
    ip_portas = defaultdict(set)
    ip_contador = defaultdict(int)

    try:
        captura = pyshark.LiveCapture(interface=interface, bpf_filter='tcp or udp')

        for i, pkt in enumerate(captura.sniff_continuously()):
            if i >= count:
                break

            if hasattr(pkt, 'ip'):
                src = pkt.ip.src
                dst = pkt.ip.dst
                proto = pkt.transport_layer
                sport = getattr(pkt[pkt.transport_layer], 'srcport', 'N/A')
                dport = getattr(pkt[pkt.transport_layer], 'dstport', 'N/A')
                tamanho = pkt.length
                hora = datetime.now().strftime("%H:%M:%S")

                dados.append([hora, src, sport, dst, dport, proto, tamanho])
                ip_portas[src].add(dport)
                ip_contador[src] += 1

                print(f"{Fore.YELLOW} {src}:{sport} → {dst}:{dport} ({proto}){Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}Erro: {e}{Style.RESET_ALL}")
        return

    mostrar_resultados(dados, ip_portas, ip_contador)

# Mostrar resultados

def mostrar_resultados(dados, ip_portas, ip_contador):
    print(f"\n{Fore.CYAN} RESUMO DA CAPTURA{Style.RESET_ALL}")
    headers = ['Horário', 'IP Origem', 'Porta Orig', 'IP Destino', 'Porta Dest', 'Protocolo', 'Tamanho']
    print(tabulate(dados, headers=headers, tablefmt='grid'))

    total = len(dados)
    protocolos = defaultdict(int)
    bytes_totais = 0

    for linha in dados:
        protocolos[linha[5]] += 1
        bytes_totais += int(linha[6])

    print(f"\n{Fore.GREEN}Estatísticas:{Style.RESET_ALL}")
    print(f" Total de pacotes: {total}")
    print(f" Total de bytes: {bytes_totais:,}")
    for p, c in protocolos.items():
        print(f"   • {p}: {c} pacotes")

    print(f"\n{Fore.MAGENTA} Detecção de IPs Suspeitos:{Style.RESET_ALL}")
    suspeitos = []
    for ip, portas in ip_portas.items():
        if len(portas) >= 5 or ip_contador[ip] >= 10:
            print(f"{Fore.RED} Suspeito: {ip} → {len(portas)} portas, {ip_contador[ip]} pacotes{Style.RESET_ALL}")
            suspeitos.append(ip)

    if suspeitos:
        ver = input(f"\n Deseja consultar detalhes dos IPs suspeitos? (s/n): ").lower()
        if ver == 's':
            for ip in suspeitos:
                consultar_ip(ip)

# Filtro por protocolo

def filtrar_por_protocolo(interface='any', protocolo='http', count=5):
    filtros = {
        'http': 'tcp port 80',
        'https': 'tcp port 443',
        'dns': 'udp port 53',
        'ssh': 'tcp port 22'
    }
    filtro = filtros.get(protocolo.lower(), 'tcp port 80')
    print(f"{Fore.BLUE} Capturando {count} pacotes {protocolo.upper()}{Style.RESET_ALL}")

    try:
        cap = pyshark.LiveCapture(interface=interface, bpf_filter=filtro)
        for i, pkt in enumerate(cap.sniff_continuously()):
            if i >= count:
                break
            if hasattr(pkt, 'ip'):
                print(f"{Fore.GREEN}[{datetime.now().strftime('%H:%M:%S')}] {pkt.ip.src} → {pkt.ip.dst} ({protocolo.upper()}){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Erro: {e}{Style.RESET_ALL}")

# Menu principal

def main():
    print(f"{Fore.MAGENTA}{'='*60}\n🔍 PYSHARK NETWORK ANALYZER AVANÇADO\n{'='*60}{Style.RESET_ALL}")

    while True:
        print(f"\n{Fore.CYAN} MENU:{Style.RESET_ALL}")
        print("1. Listar interfaces")
        print("2. Captura com análise de varredura")
        print("3. Filtrar por protocolo")
        print("4. Sair")

        escolha = input("Escolha (1-4): ")

        if escolha == '1':
            mostrar_interfaces()
        elif escolha == '2':
            iface = input("Interface (padrão: any): ") or "any"
            count = input_seguro("Número de pacotes (padrão: 10): ", 10, int)
            analisar_pacotes(iface, count)
        elif escolha == '3':
            iface = input("Interface (padrão: any): ") or "any"
            proto = input("Protocolo (http/https/dns/ssh): ") or "http"
            count = input_seguro("Número de pacotes (padrão: 5): ", 5, int)
            filtrar_por_protocolo(iface, proto, count)
        elif escolha == '4':
            print(" Encerrando...")
            break
        else:
            print("Opção inválida.")

if __name__ == "__main__":
    try:
        test = pyshark.LiveCapture(interface="any")
        test.close()
        main()
    except Exception as e:
        print(f"{Fore.RED} Erro de permissão: {e}{Style.RESET_ALL}\n💡 Use sudo ou execute como administrador.")
