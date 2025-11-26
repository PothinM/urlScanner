# 🦠 VirusTotal URL Scanner

Un outil simple en Python pour analyser des URLs via l'API v3 de VirusTotal. Ce script envoie une URL, attend l'analyse de manière asynchrone et retourne le verdict de sécurité (Malveillant/Sain).

## 🚀 Fonctionnalités

- Authentification sécurisée via fichier `.env`
- Gestion de l'analyse asynchrone (attente automatique du résultat)
- Affichage clair des statistiques (Harmless, Malicious, Suspicious)
- Compatible aussi avec macOS (gestion du problème SSL `urllib3`)

## 📋 Prérequis

- Python 3.x
- Une clé API VirusTotal (gratuite) : [Obtenir une clé](https://www.virustotal.com/)

## 🛠 Installation

1. Clonez ce dépôt :
   ```bash
   git clone [https://github.com/PothinM/urlScanner.git](https://github.com/PothinM/urlScanner.git)
   cd urlScanner
