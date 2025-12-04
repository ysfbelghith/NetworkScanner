#!/usr/bin/env python3
"""
Network Scanner Basique
Ce script découvre les appareils sur le réseau local en utilisant ARP ou ping.
Il affiche IP, MAC et hostname si possible.
Utilise scapy pour ARP et netifaces pour les interfaces.
"""

import sys
import csv
import argparse
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import netifaces as ni

def get_default_interface():
    """
    Détecte l'interface réseau par défaut.
    Retourne le nom de l'interface (ex: 'eth0' ou 'Ethernet').
    """
    try:
        # Obtenir la passerelle par défaut
        gws = ni.gateways()
        if 'default' in gws and gws['default']:
            # Prendre la première passerelle IPv4
            for gw in gws['default'].values():
                if isinstance(gw, tuple) and len(gw) >= 2:
                    return gw[1]  # Nom de l'interface
        # Fallback: première interface non-loopback
        interfaces = ni.interfaces()
        for iface in interfaces:
            if iface != 'lo' and not iface.startswith('lo'):
                return iface
    except Exception as e:
        print(f"Erreur lors de la détection de l'interface: {e}")
        sys.exit(1)
    return None

def get_network_cidr(interface):
    """
    Calcule le réseau en notation CIDR (ex: 192.168.1.0/24) à partir de l'interface.
    """
    try:
        addrs = ni.ifaddresses(interface)
        if ni.AF_INET in addrs:
            ip = addrs[ni.AF_INET][0]['addr']
            netmask = addrs[ni.AF_INET][0]['netmask']
            # Calcul simple du CIDR (pour /24, etc.)
            # Pour simplicité, on suppose un masque standard
            octets = netmask.split('.')
            cidr = sum(bin(int(o)).count('1') for o in octets)
            network = '.'.join(str(int(ip.split('.')[i]) & int(octets[i])) for i in range(4))
            return f"{network}/{cidr}"
    except Exception as e:
        print(f"Erreur lors du calcul du réseau: {e}")
        sys.exit(1)
    return None

def arp_scan(network):
    """
    Effectue un scan ARP sur le réseau donné.
    Retourne une liste de dicts: [{'ip': '192.168.1.1', 'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'router'}]
    """
    devices = []
    try:
        # Créer la requête ARP
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # Envoyer et recevoir
        result = srp(packet, timeout=3, verbose=0)[0]

        for sent, received in result:
            device = {
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': 'N/A'  # On essaiera de le résoudre plus tard
            }
            devices.append(device)
    except Exception as e:
        print(f"Erreur ARP scan: {e}. Tentative avec ping sweep.")
        return ping_sweep(network)
    return devices

def ping_sweep(network):
    """
    Fallback: scan par ping si ARP échoue.
    Note: ne récupère que IP, pas MAC.
    """
    devices = []
    try:
        # Extraire les adresses IP du réseau (simplifié pour /24)
        if '/' in network:
            base, cidr = network.split('/')
            base_octets = base.split('.')
            for i in range(1, 255):  # Scan 1-254
                ip = f"{base_octets[0]}.{base_octets[1]}.{base_octets[2]}.{i}"
                packet = IP(dst=ip)/ICMP()
                reply = sr1(packet, timeout=1, verbose=0)
                if reply:
                    devices.append({
                        'ip': ip,
                        'mac': 'N/A (ping only)',
                        'hostname': 'N/A'
                    })
    except Exception as e:
        print(f"Erreur ping sweep: {e}")
    return devices

def resolve_hostnames(devices):
    """
    Essaie de résoudre les hostnames pour chaque IP.
    """
    import socket
    for device in devices:
        try:
            hostname = socket.gethostbyaddr(device['ip'])[0]
            device['hostname'] = hostname
        except:
            pass  # Garde 'N/A'

def display_results(devices):
    """
    Affiche les résultats en tableau simple.
    """
    print("\nAppareils découverts:")
    print("-" * 50)
    print(f"{'IP':<15} {'MAC':<18} {'Hostname'}")
    print("-" * 50)
    for device in devices:
        print(f"{device['ip']:<15} {device['mac']:<18} {device['hostname']}")

def export_csv(devices, filename='scan_results.csv'):
    """
    Exporte les résultats en CSV.
    """
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['ip', 'mac', 'hostname']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(devices)
    print(f"Résultats exportés dans {filename}")

def main():
    parser = argparse.ArgumentParser(description="Network Scanner Basique")
    parser.add_argument('--export', type=str, help="Exporter en CSV (ex: --export results.csv)")
    args = parser.parse_args()

    print("Network Scanner Basique")
    print("========================")

    # Étape 1: Détecter l'interface
    interface = get_default_interface()
    if not interface:
        print("Impossible de détecter l'interface réseau.")
        sys.exit(1)
    print(f"Interface détectée: {interface}")

    # Étape 2: Calculer le réseau
    network = get_network_cidr(interface)
    if not network:
        print("Impossible de calculer le réseau.")
        sys.exit(1)
    print(f"Réseau: {network}")

    # Étape 3: Scanner
    print("Scan en cours... (peut prendre quelques secondes)")
    devices = arp_scan(network)
    if not devices:
        print("Aucun appareil trouvé.")
        return

    # Résoudre hostnames
    resolve_hostnames(devices)

    # Afficher
    display_results(devices)

    # Exporter si demandé
    if args.export:
        export_csv(devices, args.export)

if __name__ == "__main__":
    # Vérifier si admin/root (important pour ARP)
    import os
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Attention: Lancez en tant qu'administrateur pour de meilleurs résultats.")
        except:
            pass
    else:  # Linux/Mac
        if os.geteuid() != 0:
            print("Attention: Lancez avec sudo pour de meilleurs résultats.")

    main()
