import requests
import json
import os
import time

# === CONFIGURATION ===
PVWA_URL = "https://cyberark.tondomaine.local"
USERNAME = "ton_utilisateur"
PASSWORD = "ton_mot_de_passe"
BASE_URL = f"{PVWA_URL}/PasswordVault/api"
VERIFY_SSL = False

# === SETUP ===
HEADERS = {"Content-Type": "application/json"}
OUTPUT_DIR = "cyberark_data"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def save_to_file(name, content):
    path = os.path.join(OUTPUT_DIR, name)
    with open(path, "w") as f:
        json.dump(content, f, indent=2)
    print(f"\U0001F4C1 Sauvegardé : {path}")

def test_token(auth_header_value):
    test_url = f"{BASE_URL}/LoginsInfo"
    headers = HEADERS.copy()
    headers["Authorization"] = auth_header_value
    print(f"\U0001F50D Test token sur {test_url} avec header:", auth_header_value[:30], "...")
    res = requests.get(test_url, headers=headers, verify=VERIFY_SSL)
    print("\U0001F50D Code HTTP:", res.status_code)
    if res.status_code == 200:
        print("✅ Token accepté.")
        return auth_header_value
    else:
        print("❌ Token refusé.")
        return None

def authenticate():
    print("🔐 Authentification en cours...")
    url = f"{BASE_URL}/Auth/cyberark/Logon"
    payload = {"username": USERNAME, "password": PASSWORD}
    try:
        res = requests.post(url, json=payload, headers=HEADERS, verify=VERIFY_SSL)
        res.raise_for_status()
        token = res.text.strip('"')
        print("✅ Authentification réussie.")
        print("🔑 Token reçu :", token[:20], "...")

        bearer_auth = f"Bearer {token}"
        simple_auth = token

        selected_auth = test_token(bearer_auth) or test_token(simple_auth)
        if not selected_auth:
            raise Exception("Aucun format de token accepté")

        HEADERS["Authorization"] = selected_auth
        return token

    except requests.exceptions.RequestException as e:
        print("❌ Échec de l'authentification :", e)
        raise

def get_data(endpoint, filename, paginated=True, limit=100, max_pages=50):
    print(f"\n\U0001F4E1 Requête GET {endpoint}")
    results = []
    offset = 0
    last_page_data = None

    try:
        for page in range(max_pages):
            url = f"{BASE_URL}{endpoint}"
            if paginated:
                url += f"?limit={limit}&offset={offset}"

            print(f"➡️ {url}")
            print(f"📋 Headers: {HEADERS}")

            res = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)

            if res.status_code != 200:
                print(f"❌ Erreur HTTP {res.status_code} pour {url}")
                print("⛔ Contenu:", res.text)
                break

            data = res.json()
            chunk = data.get("value") if isinstance(data, dict) and "value" in data else data
            if not chunk or chunk == last_page_data:
                print("🛑 Fin des données ou boucle détectée.")
                break

            print(f"📦 Page {page + 1} : {len(chunk)} éléments")
            results.extend(chunk if isinstance(chunk, list) else [chunk])
            last_page_data = chunk
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
