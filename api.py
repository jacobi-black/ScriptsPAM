import requests
import json
import os
import time

BASE_URL = "https://<PVWA_URL>/PasswordVault/api"
USERNAME = "<your_username>"
PASSWORD = "<your_password>"

HEADERS = {
    "Content-Type": "application/json"
}

OUTPUT_DIR = "cyberark_data"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def save_to_file(name, content):
    with open(os.path.join(OUTPUT_DIR, name), "w") as f:
        json.dump(content, f, indent=2)

def authenticate():
    auth_url = f"{BASE_URL}/Auth/cyberark/Logon"
    payload = {"username": USERNAME, "password": PASSWORD}
    res = requests.post(auth_url, json=payload, headers=HEADERS, verify=False)
    res.raise_for_status()
    token = res.text.strip('"')
    HEADERS["Authorization"] = f"Bearer {token}"
    return token

def fetch_paginated(endpoint, filename, key=None, limit=100, max_pages=100):
    all_data = []
    offset = 0
    for _ in range(max_pages):
        url = f"{BASE_URL}{endpoint}?limit={limit}&offset={offset}"
        res = requests.get(url, headers=HEADERS, verify=False)
        if res.status_code != 200:
            print(f"❌ Failed to fetch {endpoint} with offset {offset}")
            break

        data = res.json()
        chunk = data[key] if key and key in data else data.get("value") or data
        if not chunk:
            break
        all_data.extend(chunk)
        offset += limit
        time.sleep(0.5)  # Eviter surcharge API
    save_to_file(filename, all_data)

def fetch_simple(endpoint, filename):
    url = f"{BASE_URL}{endpoint}"
    res = requests.get(url, headers=HEADERS, verify=False)
    res.raise_for_status()
    save_to_file(filename, res.json())

def main():
    try:
        authenticate()

        # Endpoints paginés
        fetch_paginated("/Accounts", "accounts.json")
        fetch_paginated("/Safes", "safes.json")
        fetch_paginated("/Platforms", "platforms.json")
        fetch_paginated("/Users", "users.json")
        fetch_paginated("/LiveSessions", "live_sessions.json")
        fetch_paginated("/Recordings", "recordings.json")
        fetch_paginated("/MyRequests", "my_requests.json")
        fetch_paginated("/IncomingRequests", "incoming_requests.json")

        # Endpoint simple
        fetch_simple("/ComponentsMonitoringSummary", "components_monitoring.json")

        print(f"✅ Tous les fichiers JSON sont dans : {OUTPUT_DIR}/")

    except requests.HTTPError as e:
        print(f"❌ Erreur HTTP : {e.response.status_code} - {e.response.text}")
    except Exception as e:
        print(f"❌ Erreur : {e}")

if __name__ == "__main__":
    main()