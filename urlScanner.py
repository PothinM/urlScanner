import os
import time
import requests
from dotenv import load_dotenv

# 1. Chargement de la configuration
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    print("❌ Erreur : Clé API manquante dans le fichier .env")
    exit()

# Configuration commune
HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY
}

def submit_url_for_scan(target_url):
    """Envoie l'URL à scanner et retourne l'ID de l'analyse."""
    endpoint = "https://www.virustotal.com/api/v3/urls"
    data = {"url": target_url}
    headers = HEADERS.copy()
    headers["content-type"] = "application/x-www-form-urlencoded"

    response = requests.post(endpoint, headers=headers, data=data)
    response.raise_for_status()
    
    analysis_id = response.json()['data']['id']
    print(f"🚀 URL envoyée. ID d'analyse reçu : {analysis_id}")
    return analysis_id

def get_analysis_result(analysis_id):
    """Sonde l'API jusqu'à ce que l'analyse soit terminée."""
    endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    print("⏳ Analyse en cours (attente du résultat)...")
    
    while True:
        response = requests.get(endpoint, headers=HEADERS)
        response.raise_for_status()
        result = response.json()
        
        # On vérifie le statut de l'analyse
        status = result['data']['attributes']['status']
        
        if status == "completed":
            return result['data']['attributes']['stats']
        elif status == "queued":
            print(".", end="", flush=True) # Petit effet visuel d'attente
        
        # On attend 5 secondes avant de redemander pour ne pas spammer l'API
        time.sleep(5)

if __name__ == "__main__":
    url_to_test = input("Entrez l'URL à scanner : ")
    
    try:
        # Étape 1 : Envoyer
        scan_id = submit_url_for_scan(url_to_test)
        
        # Étape 2 : Attendre et récupérer le résultat
        stats = get_analysis_result(scan_id)
        
        # Étape 3 : Affichage propre
        print("\n" + "="*40)
        print("📊 RÉSULTATS DE L'ANALYSE")
        print("="*40)
        print(f"✅ Inoffensif (Harmless) : {stats['harmless']}")
        print(f"⚠️ Malveillant (Malicious) : {stats['malicious']}")
        print(f"❓ Suspect (Suspicious)   : {stats['suspicious']}")
        print("="*40)
        
        if stats['malicious'] > 0:
            print("🚨 ATTENTION : Cette URL est détectée comme dangereuse !")
        else:
            print("👍 L'URL semble saine.")

    except Exception as e:
        print(f"\n❌ Une erreur s'est produite : {e}")
