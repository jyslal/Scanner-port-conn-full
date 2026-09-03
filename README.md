# 🔍 Scanner Réseau Unifié

Un outil modulaire de reconnaissance réseau, combinant plusieurs méthodes de scan (ICMP, TCP, UDP, SNMP, SYN) derrière un point d'entrée unique.  
Développé en **solo**, en **une semaine**, dans le cadre d'un projet personnel alliant **sécurité offensive**, **programmation Python**, **réseau** et **Linux**.

---

## 📦 Fonctionnalités

| Module | Mode | Description |
|--------|------|-------------|
| `scanConn.py` | `--connectivity` | Diagnostic de connectivité (ICMP, SYN, ACK) – détecte un hôte actif même si l'ICMP est filtré. |
| `scanTCP.py` | `--tcp` | Scanner TCP classique via sockets Python (connect scan). Supporte une liste de ports ou un scan complet (1-1023). |
| `scanUDP.py` | `--udp` | Scanner UDP avec envoi de sonde et écoute de réponse. Détecte les ports ouverts, filtrés ou fermés. |
| `scanUDP.py` | `--snmp` | Test SNMP sur le port 161 avec les communautés courantes (`public`, `private`, etc.) – construction manuelle des paquets. |
| `scanVerbeux.py` | `--syn-verbose` | Scan TCP SYN détaillé avec Scapy – analyse les réponses SYN-ACK, RST, affiche les échanges. |

---

## 🧱 Architecture

```
Scanner/
├── main.py               # Point d'entrée unique (argparse)
├── scanConn.py           # Test de connectivité
├── scanTCP.py            # Scanner TCP (socket)
├── scanUDP.py            # Scanner UDP + SNMP
├── scanVerbeux.py        # Scanner SYN verbeux (Scapy)
├── utils.py              # Fonctions communes (get_service_name, etc.)
└── README.md
```

Chaque scanner est indépendant et peut être utilisé séparément.  
Le `main.py` les agrège avec des modes **mutuellement exclusifs**.

---

## ⚙️ Installation

### Prérequis
- Python 3.6+
- Bibliothèques : `scapy`, `socket` (intégré), `argparse` (intégré)

```bash
# Installer Scapy (si ce n'est pas déjà fait)
pip install scapy
```

### Téléchargement
```bash
git clone https://github.com/ton-compte/scanner-reseau-unifie.git
cd scanner-reseau-unifie
```

---

## 🚀 Utilisation

### Syntaxe générale
```bash
python3 main.py -c <CIBLE> [OPTIONS] --<MODE>
```

### Exemples

**1. Tester la connectivité d'un hôte**
```bash
python3 main.py -c 192.168.1.1 --connectivity
```

**2. Scanner TCP sur des ports spécifiques**
```bash
python3 main.py -c 192.168.1.1 --tcp -p 22 80 443
```

**3. Scanner TCP complet (1-1023)**
```bash
python3 main.py -c 192.168.1.1 --tcp
```

**4. Scanner TCP SYN verbeux (nécessite `sudo`)**
```bash
sudo python3 main.py -c 192.168.1.1 --syn-verbose -p 80 443
```

**5. Scanner UDP sur des ports**
```bash
python3 main.py -c 192.168.1.1 --udp -p 53 123 161
```

**6. Détection SNMP**
```bash
python3 main.py -c 192.168.1.1 --snmp
```

**7. Afficher l'aide**
```bash
python3 main.py -h
```

---

## 📊 Exemple de sortie

### Mode `--connectivity`
```
🎯 Cible : 8.8.8.8
============================================================
Ping - Okay : pas de filtrage ICMP détecté, hôte actif
SYN(Test) - Okay : au moins un port a répondu SYN-ACK
ACK(Test) - Unfiltered : un RST a été reçu
→ Conclusion : hôte actif, au moins un port ouvert
⏱️  Temps total : 2.14 secondes
```

### Mode `--syn-verbose`
```
[SCAN VERBOSE]
target : 192.168.1.1
------------------------------------------------
80/tcp    OPEN    http
Envoyer: SYN
Reçu: SYN-ACK
Action: RST
------------------------------------------------
```

---

## 🧠 Défis rencontrés

- **Permissions** : les scans SYN (Scapy) nécessitent `sudo` – gestion propre des erreurs.
- **Timeouts** : ajustement pour éviter de confondre hôte lent et hôte injoignable.
- **Filtrage ICMP** : utilisation de SYN/ACK en complément pour confirmer l'activité.
- **Intégration** : harmonisation des sorties et de la gestion des exceptions entre modules.

---

## 🚧 Pistes d'amélioration

| Fonctionnalité | Priorité | Temps estimé |
|----------------|----------|--------------|
| Support des plages de ports (`-p 20-25 80`) | Haute | 1-2h |
| Mode silencieux (`--quiet`) | Haute | 30min |
| Multithreading (accélération ×10) | Moyenne | 2-3h |
| Export JSON/CSV | Moyenne | 1-2h |
| Détection d'OS (fingerprinting) | Basse | 1 journée |

---

## 📄 Licence

Ce projet est open-source – vous pouvez l'utiliser, le modifier et le partager librement.

---

## 🙏 Remerciements

Développé en solo, en une semaine, avec pour seules armes :  
**Python**, **Scapy**, **la curiosité** et **beaucoup de café** ☕.

---

## ✍️ Auteur

- **Votre Nom** – [GitHub](https://github.com/ton-compte)

---

**N'hésitez pas à contribuer ou à signaler des problèmes !**  
📧 contact@exemple.com
```
