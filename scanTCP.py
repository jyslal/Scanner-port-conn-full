import socket
import argparse
import time
import errno

def get_service_name(port):
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return "unknown"


def scanner_port_tcp(cible, port):
    print("------------------------------------------------")
    if type(port) == list:
        for i in port:
            try:
                socket_prog = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_prog.settimeout(0.1)
                result= socket_prog.connect_ex((cible, i))
                if result == 0:
                    print(f"->{i}/tcp {get_service_name(i)}: OPEN")
                elif result == errno.ECONNREFUSED:
                    print(f"->{i}/tcp {get_service_name(i)}: CLOSE")
                elif result == errno.ETIMEDOUT:
                    print(f"->{i}/tcp {get_service_name(i)}: FILTRED")
                else:
                    return f"UNKNOWN ({socket_prog.connect_ex((cible, i))})" 
                socket_prog.close()
            except OSError:
                continue
    else:
        nbre_port_open = 0
        for i in range(1, 1024):
            try:
                socket_prog = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_prog.settimeout(0.1)
                if socket_prog.connect_ex((cible, i)) == 0:
                    print(f"->{i}/tcp {get_service_name(i)}: OPEN")
                    nbre_port_open += 1
                socket_prog.close()
            except OSError:
                continue
        if nbre_port_open == 0:
            print("Aucun port ouvert détecté!")
    print("------------------------------------------------")

        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Ceci est le parser de ce script")
    parser.add_argument("-c", "--cible", type= str, default="127.0.0.1")
    parser.add_argument("-p", "--port", nargs= "+", type= int)
    args = parser.parse_args() #création de l'objet args
    cible = args.cible
    port = args.port
    print("[Début du scan...]\n")
    debut = time.perf_counter()
    scanner_port_tcp(cible, port)
    fin = time.perf_counter()
    print(f"\n[Fin du scan...] \nTime -> {fin - debut:.2f} (s) ")


