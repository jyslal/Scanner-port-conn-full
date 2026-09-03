from scapy.all import TCP, IP, sr1, L3RawSocket, conf
import random
import socket
import argparse
import time

def get_service_name(port):
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return "unknown"

def verbose(cible, port):
    try:
        conf.L3socket = L3RawSocket
        #Conn syn
        print(f"[SCAN VERBOSE]\n\ntarget : {cible}\n--------------------\nPORT SCANNING\n--------------------")
        if type(port) == list:
            for i in port:
                ports= random.randint(1024, 60000)
                syn = sr1(IP(dst=cible) / TCP(sport=ports, dport=i, flags="S"), timeout=0.5, verbose=False)
                if syn is None:
                    print("------------------------------------------------")
                    print(f"{i}/tcp    FILTERED    {get_service_name(i)} [AUCUNE REPONSE REÇU] | IL EST ÉGALEMENT POSSIBLE QUE L'HÔTE SOIT ÉTEINT - REFÉRER VOUS À L'OPTION SUR LA CONNICTIVITÉ POUR UNE VERIFICATION")
                    print("------------------------------------------------")
                    continue
                flag = syn[TCP].flags
                if flag.S and flag.A:
                    print("------------------------------------------------")
                    print(f"{i}/tcp    OPEN    {get_service_name(i)}")
                    print("\n\nEnvoyer: SYN\n")
                    print("Reçu: SYN-ACK\n")
                    print("Action: RST\n\n")
                    print("------------------------------------------------")
                elif flag.R:
                    print("------------------------------------------------")
                    print(f"{i}/tcp    CLOSE    {get_service_name(i)}\n\n")
                    print("Envoyer: SYN\n")
                    print("Reçu: RST\n\n")
                    print("------------------------------------------------")
        else:
            for i in range(1,1024):
                ports= random.randint(1024, 60000)
                syn = sr1(IP(dst=cible) / TCP(sport=ports, dport=i, flags="S"), timeout=0.5, verbose=False)
                if syn is None:
                    continue
                flag = syn[TCP].flags
                if flag.S and flag.A:
                    print("------------------------------------------------")
                    print(f"{i}/tcp    OPEN    {get_service_name(i)}")
                    print("\n\nEnvoyer: SYN")
                    print("\nReçu: SYN-ACK\n")
                    print("Action: RST\n\n")
                    print("------------------------------------------------")
                elif flag.R:
                    continue
                else:
                    continue
    except PermissionError:
        print("Permission root necessaire")
        return 1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Ceci est le parser de ce script")
    parser.add_argument("-c", "--cible", type= str, default="127.0.0.1")
    parser.add_argument("-p", "--port", nargs= "+", type= int)
    args = parser.parse_args() #création de l'objet args
    cible = args.cible
    port = args.port
    print("[Début du scan...]\n")
    debut = time.perf_counter()
    verbose(cible, port)
    fin = time.perf_counter()
    print(f"\n[Fin du scan...] \nTime -> {fin - debut:.2f} (s) ")

