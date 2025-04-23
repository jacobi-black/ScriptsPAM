#!/usr/bin/env python3
import argparse
import configparser
import json
import logging
import sys
from datetime import datetime, timedelta

import requests

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
      verify_ssl = true
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
        help="Fichier de config INI contenant [pam] url, user, password"
    )
    parser.add_argument(
        "--log-file", default=None,
        help="Fichier pour enregistrer les logs"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Active le mode DEBUG"
    )
    return parser.parse_args()

def paginate(session, endpoint, params, key, page_size):
    """
    Paginate over endpoints that support startIndex & count (SCIM style).
    """
    all_items = []
    start = 1
    while True:
        p = params.copy()
        p.update({"startIndex": start, "count": page_size})
        r = session.get(endpoint, params=p)
        r.raise_for_status()
        data = r.json()
        items = data.get(key, [])
        all_items.extend(items)
        logger.debug("Récup %d items depuis %s (start=%d)",
                     len(items), endpoint, start)
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
    logger.debug("Token reçu: %s…", token[:8])
    return token

def get_system_health(session, base_url):
    summary_url = f"{base_url}/SystemHealth/Summary"
    resp = session.get(summary_url)
    resp.raise_for_status()
    summary = resp.json()
    details = {}
    for comp in summary.get("components", []):
        cname = comp["component"]
        d_url = f"{base_url}/SystemHealth/Details"
        r = session.get(d_url, params={"component": cname})
        r.raise_for_status()
        details[cname] = r.json()
    return summary, details

def get_users(session, base_url, page_size):
    endpoint = f"{base_url}/Users"
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
        accts = paginate(
            session,
            f"{base_url}/Accounts",
            {"safe": name},
            "accounts",
            page_size
        )
        result[name] = accts
    return result

# --- Main ---

def main():
    args = get_args()
    cfg = load_config(args.config)

    # Reconfiguration du logging si nécessaire
    if args.log_file:
        fh = logging.FileHandler(args.log_file)
        fh.setFormatter(formatter)
        fh.setLevel(logging.DEBUG if args.debug else logging.INFO)
        logger.addHandler(fh)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        token = authenticate(cfg)
        sess = requests.Session()
        sess.headers.update({"Authorization": token})

        # Dates pour ActivityLog (30 derniers jours)
        end = datetime.utcnow()
        start = end - timedelta(days=30)

        # Collecte optimisée
        health_sum, health_det = get_system_health(sess, cfg["url"])
        users        = get_users(sess, cfg["url"], cfg["page_size"])
        psm_sess     = get_psm_sessions(sess, cfg["url"])
        activity     = get_activity_log(sess, cfg["url"], start, end)
        safes_accts  = get_safes_accounts(sess, cfg["url"], cfg["page_size"])

        dashboard = {
            "health_summary": health_sum,
            "health_details": health_det,
            "users":          {"count": len(users),      "data": users},
            "psm_sessions":   {"count": len(psm_sess),  "data": psm_sess},
            "activity":       {"count": len(activity),   "data": activity},
            "safes":          {"count": len(safes_accts),"data": safes_accts}
        }

        print(json.dumps(dashboard, indent=2, ensure_ascii=False))
    except Exception as e:
        logger.error("Échec lors de l'exécution : %s", e, exc_info=args.debug)
        sys.exit(1)

if __name__ == "__main__":
    main()