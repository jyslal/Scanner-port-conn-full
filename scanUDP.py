import socket
import argparse
import time

def scanner_port_udp(cible, ports):
    open = False
    if type(ports) == list:
        for p in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)          # très important
    
            try:
                sock.sendto(b"probe", (cible, p))
                data, addr = sock.recvfrom(1024)
                print(f"[+] Port {p} : réponse reçue → {data!r}")
                open = True
            except socket.timeout:
                print(f"[?] Port {p} : aucune réponse (ouvert|filtré|fermé)")
            except Exception as e:
                print(f"[-] Port {p} : erreur {e}")
            finally:
                sock.close()
    else:
        for p in range(1023, 2000):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)          # très important
            
            try:
                sock.sendto(b"probe", (cible, p))
                data, addr = sock.recvfrom(1024)
                print(f"[+] Port {p} (ouvert) : réponse reçue → {data!r}")
                open = True
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[-] Port {p} : erreur {e}")
            finally:
                sock.close()
        if open == False:
            print("AUCUN PORT OUVERT")
                
    
def build_snmp_get(community: str, oid_bytes: bytes, version: int = 0) -> bytes:
    """
    Construit dynamiquement un paquet SNMP GET.
    version: 0 = SNMPv1, 1 = SNMPv2c
    """
    community_bytes = community.encode()
    
    # OID wrapper: 06 <len> <oid_bytes>
    oid_field = bytes([0x06, len(oid_bytes)]) + oid_bytes #06 = Oid
    
    # VarBind: 30 <len> <oid_field> 05 00 (NULL value)
    varbind = bytes([0x30, len(oid_field) + 2]) + oid_field + bytes([0x05, 0x00])# 03 sequence et (05 00) = vide
    
    # VarBindList: 30 <len> <varbind>
    varbind_list = bytes([0x30, len(varbind)]) + varbind
    
    # PDU body: request-id, error-status, error-index, varbindlist
    pdu_body = bytes([0x02, 0x01, 0x04])  # request-id = 4  02= entier
    pdu_body += bytes([0x02, 0x01, 0x00])  # error-status = 0
    pdu_body += bytes([0x02, 0x01, 0x00])  # error-index = 0
    pdu_body += varbind_list
    
    # PDU: a0 <len> <pdu_body>  (0xa0 = GetRequest)
    pdu = bytes([0xa0, len(pdu_body)]) + pdu_body# a0 = ceci est une requete GET
    
    # Header: version + community
    header = bytes([0x02, 0x01, version])
    header += bytes([0x04, len(community_bytes)]) + community_bytes #04= String
    
    # Message complète
    message_body = header + pdu
    message = bytes([0x30, len(message_body)]) + message_body
    
    return message


def scanner_port_snmp(target: str, port: int = 161, timeout: float = 1.0):
    """
    Teste une liste de communities courantes sur sysDescr.0
    """
    communities = [
        "public", "private", "community", "manager", "admin",
        "cisco", "snmp", "default", "read", "write", "test"
    ]
    
    # OID sysDescr.0 = 1.3.6.1.2.1.1.1.0 (sysDescr.0) c'est l'identificateur commun retournant des informations sur le système intérrogé
    sys_descr_oid = bytes.fromhex("2b06010201010100")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    Okay = False

    try:
        for community in communities:
            for version, vname in [(0, "v1"), (1, "v2c")]:
                packet = build_snmp_get(community, sys_descr_oid, version)
                try:
                    sock.sendto(packet, (target, port))
                    data, addr = sock.recvfrom(4096)
                    Okay= True
                    return Okay
                except socket.timeout:
                    continue
    finally:
        sock.close()

    return Okay
        
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scanner UDP simple")
    parser.add_argument("-c", "--cible", default="127.0.0.1")
    parser.add_argument("-p", "--port", nargs="+", type=int, help="Un ou plusieurs ports (ex: -p 53 123 161)")
    parser.add_argument("-sn", "--snmp", action="store_true")
    args = parser.parse_args()
    print("[Début du scan...] \n")
    debut = time.perf_counter()
    print("------------------------------------------------")
    if not args.snmp:
        scanner_port_udp(args.cible, args.port)
        
    if args.snmp:
        if scanner_port_snmp(args.cible) == True:
            print("udp/161 - SNMP Open")
        else:
            print("udp/161 - SNMP Closed|filtred")
    fin = time.perf_counter()
    print("------------------------------------------------")
    print(f"\n[Fin du scan...]\nTime -> {fin - debut:.2f} (s)")