#!/usr/bin/env python3
import argparse
import configparser
import json
import logging
import os
import sys

import requests
import urllib3

# ---------------------------------------
#  CyberArk PAM Dashboard Data Exporter
# ---------------------------------------
# Extrait des données brutes depuis l'API CyberArk PAM
# et enregistre chaque appel dans un fichier JSON distinct.

# --- Configuration du Logger ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s"
)
logger = logging.getLogger("cyberark_pam_exporter")

# --- Lecture de la configuration ---
def load_config(path="config.ini"):
    cfg = configparser.ConfigParser()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg.read_file(f)
    except Exception as e:
        logger.error("Impossible de lire le fichier de configuration %s: %s", path, e)
        sys.exit(1)
    section = 'CyberArk'
    if section not in cfg:
        logger.error("Section '%s' introuvable dans %s", section, path)
        sys.exit(1)
    def get_raw(opt):
        raw = cfg.get(section, opt, fallback=None)
        if raw is None:
            logger.error("Option '%s' manquante dans la section %s", opt, section)
            sys.exit(1)
        return raw.split(';',1)[0].split('#',1)[0].strip()
    base_url_raw = get_raw('url')
    username    = get_raw('username')
    password    = get_raw('password')
    verify_raw  = get_raw('verify_ssl').lower()
    page_raw    = get_raw('page_size')
    # Parser du booléen verify_ssl
    if verify_raw in ('true','1','yes','on'):
        verify_ssl = True
    elif verify_raw in ('false','0','no','off'):
        verify_ssl = False
    else:
        logger.error("Valeur invalide pour verify_ssl: %s", verify_raw)
        sys.exit(1)
    # Parser de l'entier page_size
    try:
        page_size = int(page_raw)
    except ValueError:
        logger.error("Valeur invalide pour page_size: %s", page_raw)
        sys.exit(1)
    return {
        'base_url':   base_url_raw.rstrip('/'),
        'username':   username,
        'password':   password,
        'verify_ssl': verify_ssl,
        'page_size':  page_size,
    }

# --- Authentification ---
def authenticate(base_url, user, pwd, verify_ssl):
    url = f"{base_url}/Auth/Cyberark/Logon/"
    try:
        resp = requests.post(url, json={'username': user, 'password': pwd}, verify=verify_ssl)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.error("Échec de l'authentification : %s", e)
        sys.exit(1)
    token = resp.text.strip('"')
    logger.info("Authentification réussie")
    return token

# --- Pagination générique ---
def fetch_all(session, endpoint, params=None, list_key=None, page_size=1000):
    results = []
    offset = 0
    params = params.copy() if params else {}
    while True:
        params.update({'offset': offset, 'limit': page_size})
        resp = session.get(session.base_url + endpoint, params=params)
        resp.raise_for_status()
        data = resp.json()
        # Extraire la liste de résultats
        if list_key and isinstance(data, dict) and list_key in data:
            batch = data[list_key]
        elif isinstance(data, dict) and 'value' in data:
            batch = data['value']
        elif isinstance(data, list):
            batch = data
        else:
            # si réponse unique ou non paginée
            batch = []
        results.extend(batch)
        logger.debug("%d items récupérés pour %s (offset=%d)", len(batch), endpoint, offset)
        if len(batch) < page_size:
            break
        offset += page_size
    return results

# --- Sauvegarde JSON ---
def save_json(data, filename):
    os.makedirs('output', exist_ok=True)
    path = os.path.join('output', filename)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        logger.info("Fichier écrit : %s", path)
    except Exception as e:
        logger.error("Erreur écriture %s : %s", path, e)

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Export JSON des données CyberArk PAM")
    parser.add_argument('-c', '--config', default='config.ini', help='Chemin vers config.ini')
    parser.add_argument('--debug', action='store_true', help='Activer logs DEBUG')
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)

    cfg = load_config(args.config)
    if not cfg['verify_ssl']:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("SSL verification désactivée")

    # Authentification
    token = authenticate(cfg['base_url'], cfg['username'], cfg['password'], cfg['verify_ssl'])

    # Préparer session HTTP
    session = requests.Session()
    session.base_url = cfg['base_url']
    session.verify   = cfg['verify_ssl']
    session.headers.update({'Authorization': token, 'Content-Type': 'application/json'})

    # 1. Utilisateurs
    users = fetch_all(session, '/Users/', list_key='Users', page_size=cfg['page_size'])
    save_json({'Users': users}, 'users.json')

    # 2. Sessions PSM/PSMP
    live_sessions = fetch_all(session, '/LiveSessions', list_key='LiveSessions', page_size=cfg['page_size'])
    save_json({'LiveSessions': live_sessions}, 'livesessions.json')

    # 3. Composants - résumé
    summary_resp = session.get(f"{cfg['base_url']}/ComponentsMonitoringSummary/")
    summary_resp.raise_for_status()
    summary = summary_resp.json()
    save_json(summary, 'components_summary.json')

    # 4. Composants - détails par ID
    components = summary.get('Components', [])
    for comp in components:
        cid = comp.get('ComponentID')
        if cid:
            detail_resp = session.get(f"{cfg['base_url']}/ComponentsMonitoringDetails/{cid}/")
            detail_resp.raise_for_status()
            detail = detail_resp.json()
            save_json(detail, f'component_{cid}.json')

    # 5. Safes
    safes = fetch_all(session, '/Safes/', list_key='value', page_size=cfg['page_size'])
    save_json({'Safes': safes}, 'safes.json')

    # 6. Tous les comptes
    accounts = fetch_all(session, '/Accounts', list_key='value', page_size=cfg['page_size'])
    save_json({'Accounts': accounts}, 'accounts.json')

    # 7. Comptes par Safe
    for safe in safes:
        name = safe.get('safeName') or safe.get('SafeName')
        if name:
            accts = fetch_all(
                session,
                '/Accounts',
                params={'filter': f"safeName eq {name}"},
                list_key='value',
                page_size=cfg['page_size']
            )
            filename = f"accounts_{name.replace(' ', '_')}.json"
            save_json({'Accounts': accts}, filename)

if __name__ == '__main__':
    main()
