import requests
import json
import os
import time

# === CONFIGURATION ===
PVWA_URL = "https://cyberark.tondomaine.local"  # 🔁 Remplace ici
USERNAME = "ton_utilisateur"
PASSWORD = "ton_mot_de_passe"
BASE_URL = f"{PVWA_URL}/PasswordVault/api"
VERIFY_SSL = False  # à True en prod avec certificat valide

# === SETUP ===
HEADERS = {"Content-Type": "application/json"}
OUTPUT_DIR = "cyberark_data"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def save_to_file(name, content):
    path = os.path.join(OUTPUT_DIR, name)
    with open(path, "w") as f:
        json.dump(content, f, indent=2)
    print(f"📁 Sauvegardé : {path}")

def authenticate():
    print("🔐 Authentification en cours...")
    url = f"{BASE_URL}/Auth/cyberark/Logon"
    payload = {"username": USERNAME, "password": PASSWORD}
    try:
        res = requests.post(url, json=payload, headers=HEADERS, verify=VERIFY_SSL)
        res.raise_for_status()
        token = res.text.strip('"')
        print("✅ Authentification réussie.")
        print("🔑 Token reçu :", token[:20], "...(tronqué)")
        HEADERS["Authorization"] = f"Bearer {token}"
        return token
    except requests.exceptions.RequestException as e:
        print("❌ Échec de l'authentification :", e)
        raise

def get_data(endpoint, filename, paginated=True, limit=100, max_pages=50):
    print(f"\n📡 Requête GET {endpoint}")
    results = []
    offset = 0

    try:
        for page in range(max_pages):
            url = f"{BASE_URL}{endpoint}"
            if paginated:
                url += f"?limit={limit}&offset={offset}"

            print(f"➡️ {url}")
            res = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)

            if res.status_code != 200:
                print(f"❌ Erreur HTTP {res.status_code} pour {url}")
                print("⛔ Contenu:", res.text)
                break

            data = res.json()
            chunk = data.get("value") if isinstance(data, dict) and "value" in data else data
            if not chunk:
                print("🛑 Fin des données.")
                break

            results.extend(chunk if isinstance(chunk, list) else [chunk])
            offset += limit

            if not paginated:
                break
            time.sleep(0.5)

        save_to_file(filename, results)
    except requests.exceptions.RequestException as e:
        print(f"❌ Exception durant la requête {endpoint} :", e)

def main():
    try:
        authenticate()

        # Requêtes GET pour dashboard d’utilisation
        get_data("/Accounts", "accounts.json")
        get_data("/Safes", "safes.json")
        get_data("/Platforms", "platforms.json")
        get_data("/Users", "users.json")
        get_data("/LiveSessions", "live_sessions.json")
        get_data("/Recordings", "recordings.json")
        get_data("/MyRequests", "my_requests.json")
        get_data("/IncomingRequests", "incoming_requests.json")
        get_data("/ComponentsMonitoringSummary", "components_monitoring.json", paginated=False)

        print("\n✅ Toutes les données ont été récupérées avec succès.")

    except Exception as e:
        print("❌ Échec général :", e)

if __name__ == "__main__":
    main()