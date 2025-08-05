#!/usr/bin/env python3
"""
Extrator de CVEs a partir da saída de um scan Nmap com o script vulners.
Salva os CVEs únicos em 'vulnerabilidades.txt'
"""

import re
from pathlib import Path
import sys

def extrair_cves(texto):
    cve_regex = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    return sorted(set(cve_regex.findall(texto)))

def salvar_em_arquivo(cves, destino="vulnerabilidades.txt"):
    with open(destino, "w") as f:
        for cve in cves:
            f.write(cve.upper() + "\n")
    print(f"[✔] {len(cves)} CVEs salvos em: {destino}")

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 extrair_cves_nmap.py <arquivo_nmap.txt>")
        sys.exit(1)

    caminho = Path(sys.argv[1])
    if not caminho.exists():
        print(f"[✖] Arquivo não encontrado: {caminho}")
        sys.exit(2)

    texto = caminho.read_text(encoding="utf-8", errors="ignore")
    cves = extrair_cves(texto)
    if not cves:
        print("[!] Nenhum CVE encontrado no arquivo.")
        sys.exit(0)

    salvar_em_arquivo(cves)

if __name__ == "__main__":
    main()
