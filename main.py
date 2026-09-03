import argparse
import time
import sys
import scanConn
import scanTCP
import scanUDP
import scanVerbeux

def main():
    parser = argparse.ArgumentParser(description="scaner réseau unifié",formatter_class=argparse.RawDescriptionHelpFormatter,epilog=
    """EXEMPLES D'UTILISATION:
    # Vérifier si un hôte est actif
    python3 main.py -c 192.168.1.1 --connectivity

    # scaner TCP simple sur des ports spécifiques
    python3 main.py -c 192.168.1.1 -p 80 443 8080 --tcp

    # scaner TCP SYN verbeux (Scapy, besoin root)
    sudo python3 main.py -c 192.168.1.1 -p 22 80 --syn-verbose

    # scaner UDP (ports classiques)
    python3 main.py -c 192.168.1.1 -p 53 123 161 --udp

    # Détection SNMP (communautés par défaut)
    python3 main.py -c 192.168.1.1 --snmp

    # Scan TCP complet (1-1023) sans liste de ports
    python3 main.py -c 192.168.1.1 --tcp""")

    # Arguments communs
    parser.add_argument(
        "-c", "--cible",
        type=str,
        default="127.0.0.1",
        help="Adresse IP ou nom d'hôte cible"
    )
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        help="Liste de ports (ex: 80 443 8080) ou plage non prise en charge ici"
    )

    # Modes d'analyse (mutuellement exclusifs pour éviter les conflits)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--connectivity",
        action="store_true",
        help="Test de connectivité (ICMP, SYN, ACK) - scanConn.py"
    )
    mode_group.add_argument(
        "--tcp",
        action="store_true",
        help="scaner TCP classique (socket) - scanTCP.py"
    )
    mode_group.add_argument(
        "--syn-verbose",
        action="store_true",
        help="scaner TCP SYN verbeux (Scapy) - scanVerbeux.py"
    )
    mode_group.add_argument(
        "--udp",
        action="store_true",
        help="scaner UDP - scanUDP.py"
    )
    mode_group.add_argument(
        "--snmp",
        action="store_true",
        help="Test SNMP sur le port 161 - scanUDP.py"
    )

    args = parser.parse_args()

    print("\n" + "="*60)
    print(f"[Cible] : {args.cible}")
    print("="*60 + "\n")

    debut = time.perf_counter()

    try:
        if args.connectivity:
            print("[*] Mode : Test de connectivité")
            result = scanConn.scanner_conn_tester(args.cible)
            if result == 1:
                sys.exit(1)
            ping, syn, ack = result
            scanConn.diagnostic(ping, syn, ack)

        elif args.tcp:
            print("[*] Mode : scanner TCP (socket)")
            scanTCP.scanner_port_tcp(args.cible, args.ports)

        elif args.syn_verbose:
            print("[*] Mode : scanner TCP SYN (Scapy)")
            if args.ports is None:
                print("Aucun port spécifié, scan des 1023 premiers ports")
            scanVerbeux.verbose(args.cible, args.ports)

        elif args.udp:
            print("[*] Mode : scanner UDP")
            print("------------------------------------------------")
            scanUDP.scanner_port_udp(args.cible, args.ports)
            print("------------------------------------------------")

        elif args.snmp:
            print("[*] Mode : Détection SNMP")
            print("------------------------------------------------")
            if scanUDP.scanner_port_snmp(args.cible):
                print("udp/161 - SNMP ouvert")
            else:
                print("udp/161 - SNMP fermé ou filtré")
            print("------------------------------------------------")

    except KeyboardInterrupt:
        print("\n[!] Scan interrompu par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Erreur inattendue : {e}")
        sys.exit(1)

    fin = time.perf_counter()
    print(f"\nTemps total : {fin - debut:.2f} secondes")

if __name__ == "__main__":
    main()