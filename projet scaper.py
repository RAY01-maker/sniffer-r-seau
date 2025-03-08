from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import datetime

# Définition du fichier de log
LOG_FILE = "traffic_log.txt"

def log_traffic(log_entry):
    """Ajoute une entrée au fichier de log."""
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

def detect_anomalous_activity(packet):
    """Détecte une activité suspecte selon un critère défini."""
    if packet.haslayer(DNS):
        domain = packet[DNS].qd.qname.decode('utf-8') if packet[DNS].qd else "Unknown"
        # Critère : Détection de requêtes répétées vers le même domaine en peu de temps
        if domain in suspicious_domains:
            return "ANORMAL", f"Requêtes fréquentes vers {domain}"
    return "NORMAL", "Pas d'anomalie détectée"

def process_packet(packet):
    """Traite un paquet capturé."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status, explanation = "NORMAL", ""
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        domain = "N/A"
        
        if packet.haslayer(DNS):
            domain = packet[DNS].qd.qname.decode('utf-8') if packet[DNS].qd else "Unknown"
            status, explanation = detect_anomalous_activity(packet)
        
        log_entry = f"[{timestamp}] {src_ip} → {dst_ip}\nRequête : {protocol} / DNS\nDomaine/URL : {domain}\nStatut : {status}\nExplication : {explanation}\n"
        log_traffic(log_entry)
        print(log_entry)  # Affiche dans la console

# Liste des domaines suspects (exemple de critère de détection)
suspicious_domains = {"malicious.com", "phishing.net", "darkweb.xyz"}

# Lancer le sniffer sur l'interface spécifiée (ex: eth0, wlan0)
print("Démarrage du sniffer réseau...")
sniff(filter="udp port 53", prn=process_packet, store=False)

