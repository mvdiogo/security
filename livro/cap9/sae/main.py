# main.py

from sae import SAEImplementation
import json
import os

def salvar_em_arquivo(dados, nome_arquivo="chaves_sae.json"):
    with open(nome_arquivo, 'w') as f:
        json.dump(dados, f, indent=4)
    print(f"[+] Chaves salvas em {nome_arquivo}")

def exibir_menu():
    print("\n==== Menu SAE ====")
    print("1. Criar nova sessão SAE")
    print("2. Exibir segredo compartilhado")
    print("3. Exibir chaves derivadas")
    print("4. Salvar chaves em arquivo")
    print("5. Simular ataque de commit inválido")
    print("6. Sair")
    return input("Escolha uma opção: ")

def criar_sessao():
    password = input("Digite a senha: ").strip()
    mac1 = input("MAC do dispositivo local: ").strip()
    mac2 = input("MAC do peer: ").strip()

    sae_local = SAEImplementation(password, mac1)
    sae_peer = SAEImplementation(password, mac2)

    print("\n[+] Gerando elementos de commit...")
    commit_local = sae_local.generate_commit_element()
    commit_peer = sae_peer.generate_commit_element()

    print("[+] Processando commits...")
    try:
        sae_local.process_peer_commit(commit_peer)
        sae_peer.process_peer_commit(commit_local)
    except ValueError as e:
        print(f"[!] Erro ao processar commit: {e}")
        return None, None, None

    print("[+] Derivando chaves...")
    keys_local = sae_local.derive_keys()
    keys_peer = sae_peer.derive_keys()

    if keys_local["ptk"] != keys_peer["ptk"]:
        print("[!] Erro: PTKs não coincidem!")
    else:
        print("[✓] Sessão SAE estabelecida com sucesso.")

    return sae_local, sae_peer, keys_local

def simular_commit_invalido(sae_local):
    print("\n[!] Simulando ataque: commit inválido (scalar zero)...")
    fake_commit = {
        "scalar": 0,
        "element": b'\x00' * 32
    }
    try:
        sae_local.process_peer_commit(fake_commit)
    except ValueError as e:
        print(f"[✓] Ataque detectado e bloqueado: {e}")
    else:
        print("[✗] Falha: commit inválido foi aceito!")

def main():
    sae_local = sae_peer = keys = None

    while True:
        opcao = exibir_menu()

        if opcao == '1':
            sae_local, sae_peer, keys = criar_sessao()

        elif opcao == '2':
            if sae_local and sae_local.shared_secret:
                print(f"\n[+] Segredo compartilhado: {sae_local.shared_secret.hex()}")
            else:
                print("[!] Nenhuma sessão ativa.")

        elif opcao == '3':
            if keys:
                print("\n[+] Chaves derivadas:")
                for k, v in keys.items():
                    print(f"{k.upper()}: {v.hex()}")
            else:
                print("[!] Nenhuma chave derivada disponível.")

        elif opcao == '4':
            if keys:
                salvar_em_arquivo({k: v.hex() for k, v in keys.items()})
            else:
                print("[!] Nenhuma chave para salvar.")

        elif opcao == '5':
            if sae_local:
                simular_commit_invalido(sae_local)
            else:
                print("[!] Nenhuma sessão criada para simular ataque.")

        elif opcao == '6':
            print("Saindo...")
            break

        else:
            print("[!] Opção inválida.")


if __name__ == "__main__":
    main()
