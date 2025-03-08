# sniffer-r-seau
# Sniffer Réseau

## Introduction
Ce projet est un sniffer réseau en Python permettant de capturer le trafic, d'extraire des informations utiles et de détecter des activités suspectes.

## Installation
```bash
git clone < https://github.com/RAY01-maker/sniffer-r-seau.git>
cd sniffer-reseau
pip install -r requirements.txt
```

## Utilisation
```bash
sudo python3 sniffer.py
```

## Fonctionnalités
- Capture du trafic réseau en temps réel
- Filtrage des requêtes (HTTP, DNS)
- Extraction des adresses IP et domaines
- Détection d'activité suspecte basée sur des requêtes anormales
- Enregistrement des logs dans `traffic_log.txt`

## Exemple de log
```
[12:34:56] 192.168.1.100 → 8.8.8.8
Requête : DNS
Domaine : google.com
Statut : NORMAL
```

## Auteur
Projet réalisé par [RAY01-maker].

## Licence
MIT License.

