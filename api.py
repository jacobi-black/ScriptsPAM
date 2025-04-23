#!/usr/bin/env python3
import argparse
import configparser
import json
import logging
import sys
from datetime import datetime, timedelta

import requests
import urllib3

# --- Configuration du logging ---
logger = logging.getLogger("cyberark_pam_dashboard")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)-8s %(name)s:%(lineno)d | %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# --- Fonctions utilitaires ---

def load_config(config_file):
    """
    Charge la configuration depuis un fichier INI.
    Format attendu :
      [pam]
      url = https://PVWA_SERVER/PasswordVault/API
      user = admin
      password = secret
      verify_ssl = false      # Mettre false pour désactiver la vérif.
      page_size = 500
    """
    cfg = configparser.ConfigParser()
    cfg.read(config_file)
    return {
        "url": cfg.get("pam", "url"),
        "user": cfg.get("pam", "user"),
        "password": cfg.get("pam", "password"),
        "verify_ssl": cfg.getboolean("pam", "verify_ssl", fallback=True),
        "page_size": cfg.getint("pam", "page_size", fallback=1000)
    }

def get_args():
    parser = argparse.ArgumentParser(
        description="Récupère les métriques CyberArk PAM pour dashboard"
    )
    parser.add_argument(
        "-c", "--config", default="config.ini",
        help="Fichier INI contenant [pam] url, user, password, verify_ssl, page_size"
    )
    parser.add_argument(
        "--log-file", default=None,
        help="Chemin d'un fichier pour enregistrer les logs"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Active le mode DEBUG"
    )
    return parser.parse_args()

def paginate(session, endpoint, params, key, page_size):
    """
    Parcourt un endpoint SCIM (startIndex/count) pour récupérer tous les items.
    """
    all_items = []
    start = 1
    while True:
        p = params.copy()
        p.update({"startIndex": start, "count": page_size})
        resp = session.get(endpoint, params=p)
        resp.raise_for_status()
        data = resp.json()
        items = data.get(key, [])
        all_items.extend(items)
        logger.debug("Récupéré %d items depuis %s (startIndex=%d)", len(items), endpoint, start)
        if len(items) < page_size:
            break
        start += page_size
    return all_items

# --- Endpoints CyberArk PAM ---

def authenticate(cfg):
    url = f"{cfg['url'].rstrip('/')}/Auth/Cyberark/Logon"
    payload = {"username": cfg["user"], "password": cfg["password"]}
    logger.info("Authentification auprès de %s", url)
    resp = requests.post(url, json=payload, verify=cfg["verify_ssl"])
    resp.raise_for_status()
    token = resp.text.strip('"')
    logger.debug("Token (début): %s…", token[:8])
    return token

def get_system_health(session, base_url):
    summary_url = f"{base_url}/SystemHealth/Summary"
    resp = session.get(summary_url)
    resp.raise_for_status()
    summary = resp.json()
    details = {}
    for comp in summary.get("components", []):
        cname = comp["component"]
        detail_url = f"{base_url}/SystemHealth/Details"
        r = session.get(detail_url, params={"component": cname})
        r.raise_for_status()
        details[cname] = r.json()
    return summary, details

def get_users(session, base_url, page_size):
    endpoint = f"{base_url}/Users"
    # SCIM pagination via startIndex & count
    return paginate(session, endpoint, {}, "users", page_size)

def get_psm_sessions(session, base_url):
    url = f"{base_url}/PSM/Session/GetLiveSessions"
    resp = session.get(url)
    resp.raise_for_status()
    return resp.json().get("sessions", [])

def get_activity_log(session, base_url, start, end):
    url = f"{base_url}/Reports/ActivityLog"
    params = {
        "fromDate": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "toDate":   end.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    resp = session.get(url, params=params)
    resp.raise_for_status()
    return resp.json().get("records", [])

def get_safes_accounts(session, base_url, page_size):
    safes = paginate(session, f"{base_url}/Safes", {}, "safes", page_size)
    result = {}
    for s in safes:
        name = s["safeName"]
        accounts = paginate(
            session,
            f"{base_url}/Accounts",
            {"safe": name},
            "accounts",
            page_size
        )
        result[name] = accounts
    return result

# --- Main ---

def main():
    args = get_args()
    cfg = load_config(args.config)

    # Reconfigurer le logger si demandé
    if args.log_file:
        fh = logging.FileHandler(args.log_file)
        fh.setFormatter(formatter)
        fh.setLevel(logging.DEBUG if args.debug else logging.INFO)
        logger.addHandler(fh)
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.DEBUG)

    # Gérer SSL verification et warnings
    if not cfg["verify_ssl"]:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("Vérification SSL désactivée (verify_ssl=False)")

    try:
        # Authentification
        token = authenticate(cfg)

        # Créer une session partagée pour tous les appels
        sess = requests.Session()
        sess.verify = cfg["verify_ssl"]        # <-- propagate verify_ssl
        sess.headers.update({"Authorization": token})

        # Dates pour le rapport d'activité (30 derniers jours)
        end = datetime.utcnow()
        start = end - timedelta(days=30)

        # Collecte des métriques
        health_summary, health_details = get_system_health(sess, cfg["url"])
        users    = get_users(sess, cfg["url"], cfg["page_size"])
        psm_sess = get_psm_sessions(sess, cfg["url"])
        activity = get_activity_log(sess, cfg["url"], start, end)
        safes    = get_safes_accounts(sess, cfg["url"], cfg["page_size"])

        # Assemblage du payload
        dashboard = {
            "health_summary": health_summary,
            "health_details": health_details,
            "users":          {"count": len(users),     "data": users},
            "psm_sessions":   {"count": len(psm_sess), "data": psm_sess},
            "activity":       {"count": len(activity),  "data": activity},
            "safes":          {"count": len(safes),     "data": safes}
        }

        print(json.dumps(dashboard, indent=2, ensure_ascii=False))

    except Exception as e:
        logger.error("Échec lors de l'exécution : %s", e, exc_info=args.debug)
        sys.exit(1)

if __name__ == "__main__":
    main()