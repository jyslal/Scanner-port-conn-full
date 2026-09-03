from scapy.all import IP, TCP, ICMP, sr1, conf, L3RawSocket
import time
import argparse

def scanner_conn_tester(cible):
    try:
        conf.L3socket = L3RawSocket
    
        # test icmp
        ping = sr1(IP(dst=cible) / ICMP(type=8, code=0), timeout=2, verbose=False)
        check_ping = ping is not None and ping[ICMP].type == 0

        if not check_ping:
            # Hôte probablement injoignable : un seul port testé suffit pour confirmer,
            # pas la peine de scanner 1023 ports pour un timeout quasi certain
            check_syn = False
            syn = sr1(IP(dst=cible) / TCP(sport=18888, dport=80, flags="S"), timeout=1, verbose=False)
            if syn is not None and syn.haslayer(TCP) and syn[TCP].flags.S and syn[TCP].flags.A:
                check_syn = True  # rare mais possible : ICMP bloqué alors que TCP passe

            check_ack = False
            ack = sr1(IP(dst=cible) / TCP(sport=18888, dport=80, flags="A"), timeout=1, verbose=False)
            if ack is not None and ack.haslayer(TCP) and ack[TCP].flags.R:
                check_ack = True

            return check_ping, check_syn, check_ack

        # Hôte confirmé actif : là ça vaut le coup de scanner les 1023 ports
        check_syn = False
        for i in range(1, 1024):
            syn = sr1(IP(dst=cible) / TCP(sport=18888, dport=i, flags="S"), timeout=1, verbose=False)
            if syn is not None and syn.haslayer(TCP):
                flag = syn[TCP].flags
                if flag.S and flag.A:
                    check_syn = True
                    break

        check_ack = False
        for i in range(1, 1024):
            ack = sr1(IP(dst=cible) / TCP(sport=18888, dport=i, flags="A"), timeout=1, verbose=False)
            if ack is not None and ack.haslayer(TCP):
                flag = ack[TCP].flags
                if flag.R:
                    check_ack = True
                    break

        return check_ping, check_syn, check_ack
    except PermissionError:
        print("Permission root necessaire")
        return 1

def diagnostic(ping, syn, ack):
    print("------------------------------------------------------------------------------------------------------------------------------------------------")
    if ping:
        print("Ping - Okay : pas de filtrage ICMP détecté, hôte actif")
    else:
        print("Ping - Echec : ICMP potentiellement filtré (ne préjuge pas encore de l'état de l'hôte, l'ICMP peut être bloqué indépendamment du TCP)")

    if syn:
        print("SYN(Test) - Okay : au moins un port a répondu SYN-ACK → hôte actif, port ouvert confirmé")
    else:
        print("SYN(Test) - Echec : aucun port testé n'a répondu ouvert (fermé, filtré, ou test insuffisant)")

    if ack:
        print("ACK(Test) - Unfiltered : un RST a été reçu → la pile TCP a répondu, donc l'hôte est CONFIRMÉ actif")
    else:
        print("ACK(Test) - Filtered : aucun RST reçu → pare-feu stateful bloquant les ACK non sollicités, ou hôte injoignable")
    
    print()
    # Synthèse
    if not ping and not syn and not ack:
        print("→ Conclusion : aucune réponse sur aucun protocole testé → hôte très probablement inactif ou totalement filtré")
    elif syn and ack:
        print("→ Conclusion : hôte actif, au moins un port ouvert, aucun filtrage TCP détecté sur les ports testés (résultat fiable)")
    elif syn and not ack:
        print("→ Conclusion : hôte actif (port ouvert confirmé via SYN), mais l'ACK est filtré ailleurs → signature typique d'un pare-feu stateful (laisse passer le SYN mais bloque les ACK hors connexion établie), à creuser port par port")
    elif not syn and ack:
        # RST reçu = hôte forcément vivant, quel que soit le ping
        print("→ Conclusion : hôte CONFIRMÉ actif (RST reçu sur l'ACK, réponse impossible d'un hôte éteint), mais aucun port ouvert parmi ceux testés → ports probablement fermés plutôt que filtrés")
    elif not syn and not ack and ping:
        print("→ Conclusion : hôte actif (ping répond) mais tout le trafic TCP testé est filtré → pare-feu bloquant spécifiquement TCP tout en laissant passer l'ICMP")
    print("------------------------------------------------------------------------------------------------------------------------------------------------")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Ceci est le parser de ce script")
    parser.add_argument("-c", "--cible", type=str, default="127.0.0.1")
    args = parser.parse_args()
    print("[Début du scan...]\n")
    debut = time.perf_counter()
    result = scanner_conn_tester(args.cible)   # on appelle une seule fois
    if result == 1:
        pass   # l'erreur PermissionError a déjà été affichée dans la fonction
    else:
        # result est un tuple (ping, syn, ack), on le dépaquette
        ping, syn, ack = result
        diagnostic(ping, syn, ack)    
    fin = time.perf_counter()
    print(f"\n[Fin du scan...] \nTime -> {fin - debut:.2f} (s) ")
