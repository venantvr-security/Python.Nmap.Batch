import ipaddress
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty

import yaml
from dotenv import load_dotenv
from flask import Flask, render_template, Response, request, jsonify

from scanners.Hping3Scanner import Hping3Scanner
from scanners.MasscanScanner import MasscanScanner
from scanners.NetcatScanner import NetcatScanner
from scanners.NmapScanner import NmapScanner
from scanners.ScapyScanner import ScapyScanner

# Charger le fichier .env
load_dotenv()

# Configuration Flask
app = Flask(__name__)
app.config['DEBUG'] = True

# Configuration des logs avec horodatage
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger()

# Fichiers JSON
ACTIVE_IPS_FILE = "active_ips.json"
PROGRESS_FILE = "progress_ips.txt"
SUMMARY_FILE = "summary.json"

# Liste des plages d'IP à scanner
IP_RANGES = os.getenv("IP_RANGES", "30.31.32.33").split(",")
logger.info(f"Plages IP chargées : {IP_RANGES}")

# Paramètres de parallélisation
INITIAL_MAX_WORKERS = 1
MIN_WORKERS = 1
MAX_WORKERS = 10

# Variables globales
stop_flag = False
success_rate = 0.0
scan_thread = None
active_processes = []
event_queue = Queue()

# Initialisation des scanners
nmap_scanner = NmapScanner(strategy="basic", active_processes=active_processes, yaml_file="strategies/nmap_strategies.yaml")
netcat_scanner = NetcatScanner(strategy="stealth", active_processes=active_processes, yaml_file="strategies/netcat_strategies.yaml")
scapy_scanner = ScapyScanner(strategy="stealth", active_processes=active_processes, yaml_file="strategies/scapy_strategies.yaml")
masscan_scanner = MasscanScanner(strategy="stealth", active_processes=active_processes, yaml_file="strategies/masscan_strategies.yaml")
hping3_scanner = Hping3Scanner(strategy="stealth", active_processes=active_processes, yaml_file="strategies/hping3_strategies.yaml")

scanner_map = {
    "nmap": nmap_scanner,
    "netcat": netcat_scanner,
    "scapy": scapy_scanner,
    "masscan": masscan_scanner,
    "hping3": hping3_scanner
}
current_scanner = nmap_scanner

# Gestion de l'arrêt propre
# noinspection PyUnresolvedReferences,PyUnusedLocal
def signal_handler(sig, frame):
    global stop_flag
    stop_flag = True
    logger.info("Signal d'arrêt reçu (Ctrl+C), arrêt en cours...")
    for proc in active_processes:
        if proc.poll() is None:
            proc.terminate()
    if scan_thread and scan_thread.is_alive():
        scan_thread.join(timeout=5)
    logger.info("Serveur arrêté proprement")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Générer toutes les adresses IP
def generate_all_ips(ranges):
    all_ips = []
    for cidr in ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            all_ips.extend([str(ip) for ip in network.hosts()])
        except ValueError as e:
            logger.error(f"Erreur dans la plage {cidr} : {e}")
            all_ips.append(cidr)
    logger.info(f"Total IPs générées : {len(all_ips)}")
    return all_ips

# Charger les IPs déjà scannées
def load_progress():
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE, "r") as f:
                return set(line.strip() for line in f if line.strip())
        except Exception as e:
            logger.error(f"Erreur lors de la lecture de {PROGRESS_FILE} : {e}")
            return set()
    return set()

# Sauvegarder une IP terminée
def save_progress(ip):
    try:
        with open(PROGRESS_FILE, "a") as f:
            f.write(f"{ip}\n")
    except Exception as e:
        logger.error(f"Erreur lors de l'écriture dans {PROGRESS_FILE} : {e}")

# Sauvegarder les IPs actives en JSON
# noinspection PyTypeChecker
def save_active_ip(ip, scan_result, os_info, versions, vulns):
    entry = {
        "ip": ip,
        "timestamp": time.ctime(),
        "os": os_info if os_info else "Unknown",
        "ports": [{"port": p, "version": versions.get(p, "Unknown")} for p in versions] if versions else scan_result.get("ports", []),
        "vulnerabilities": vulns if vulns else [],
        "raw_result": scan_result
    }
    try:
        if os.path.exists(ACTIVE_IPS_FILE):
            with open(ACTIVE_IPS_FILE, "r") as f:
                data = json.load(f)
        else:
            data = []
        data.append(entry)
        with open(ACTIVE_IPS_FILE, "w") as f:
            json.dump(data, f, indent=4)
        logger.info(f"IP {ip} sauvegardée dans {ACTIVE_IPS_FILE}")
    except Exception as e:
        logger.error(f"Erreur lors de l'écriture dans {ACTIVE_IPS_FILE} : {e}")

# Générer un rapport synthétique en JSON avec incrémentation
# noinspection PyTypeChecker
def generate_summary(total_scanned, active_count, all_ports, all_vulns):
    port_counter = Counter(all_ports)
    vuln_counter = Counter(all_vulns)
    new_entry = {
        "timestamp": time.ctime(),
        "total_scanned": total_scanned,
        "active_ips": active_count,
        "top_ports": dict(port_counter.most_common(5)),
        "top_vulnerabilities": dict(vuln_counter.most_common(5))
    }
    try:
        if os.path.exists(SUMMARY_FILE):
            with open(SUMMARY_FILE, "r") as f:
                summary_data = json.load(f)
                if not isinstance(summary_data, list):
                    summary_data = [summary_data]
        else:
            summary_data = []
        summary_data.append(new_entry)
        with open(SUMMARY_FILE, "w") as f:
            json.dump(summary_data, f, indent=4)
        logger.info(f"Résumé mis à jour dans {SUMMARY_FILE}")
    except Exception as e:
        logger.error(f"Erreur lors de l'écriture dans {SUMMARY_FILE} : {e}")


# Nouvelle route pour récupérer les stratégies
@app.route('/get_strategies/<scanner_type>')
def get_strategies(scanner_type):
    if scanner_type == "nmap":
        yaml_file = "strategies/nmap_strategies.yaml"
    elif scanner_type == "netcat":
        yaml_file = "strategies/netcat_strategies.yaml"
    else:
        return jsonify({"error": "Scanner type inconnu"}), 400

    try:
        with open(yaml_file, 'r') as file:
            data = yaml.safe_load(file)
            strategies = list(data['strategies'].keys())
        return jsonify({"strategies": strategies})
    except FileNotFoundError:
        return jsonify({"error": f"Fichier {yaml_file} non trouvé"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Fonction de scan en arrière-plan
def scan_background():
    global stop_flag, success_rate, scan_thread, current_scanner
    logger.info("Démarrage du scan")
    event_queue.put({'event': 'progress', 'data': {'message': f"[{time.ctime()}] Scan démarré"}})

    all_ips = generate_all_ips(IP_RANGES)
    total_ips = len(all_ips)
    if total_ips == 0:
        logger.error("Aucune IP valide générée")
        event_queue.put({'event': 'progress', 'data': {'message': f"[{time.ctime()}] Erreur : Aucune IP à scanner"}})
        return
    logger.info(f"Total IPs à scanner : {total_ips}")

    completed_ips = load_progress()
    ips_to_scan = [ip for ip in all_ips if ip not in completed_ips]
    remaining_ips = len(ips_to_scan)
    if remaining_ips == 0:
        logger.info("Toutes les IPs ont déjà été scannées")
        event_queue.put({'event': 'progress', 'data': {'message': f"[{time.ctime()}] Toutes les IPs ont déjà été scannées"}})
        generate_summary(total_ips, 0, [], [])
        return

    event_queue.put({'event': 'progress', 'data': {'message': f"[{time.ctime()}] IPs restantes à scanner : {remaining_ips}"}})

    current_workers = INITIAL_MAX_WORKERS
    processed_count = len(completed_ips)
    active_count = 0
    all_ports = []
    all_vulns = []

    while ips_to_scan and not stop_flag:
        batch_size = min(current_workers, len(ips_to_scan))
        batch = ips_to_scan[:batch_size]
        ips_to_scan = ips_to_scan[batch_size:]

        success_count = 0
        logger.info(f"Début du batch avec {batch_size} IPs : {batch}")
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            future_to_ip = {executor.submit(current_scanner.scan, ip, str(uuid.uuid4()), event_queue, lambda: stop_flag): ip for ip in batch}

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                processed_count += 1
                try:
                    ip, success, error, details, _ = future.result()
                    if success:
                        success_count += 1
                        save_progress(ip)
                        if details.get("ports"):
                            active_count += 1
                            all_ports.extend(details["ports"])
                            all_vulns.extend(details.get("vulns", []))
                    progress_msg = f"[{time.ctime()}] Progression : {processed_count}/{total_ips} ({(processed_count / total_ips) * 100:.2f}%)"
                    event_queue.put({'event': 'progress', 'data': {'message': progress_msg}})
                    logger.info(f"Message de progression envoyé : {progress_msg}")
                except Exception as e:
                    logger.error(f"Erreur inattendue pour {ip} : {e}")
                    event_queue.put({'event': 'progress', 'data': {'message': f"[{time.ctime()}] Erreur pour {ip} : {e}"}})

        success_rate = success_count / batch_size if batch_size > 0 else 0
        if success_rate < 0.7 and current_workers > MIN_WORKERS:
            current_workers -= 1
            logger.info(f"Réduction de parallélisation à {current_workers} (taux de succès : {success_rate:.2f})")
        elif success_rate > 0.9 and current_workers < MAX_WORKERS:
            current_workers += 1
            logger.info(f"Augmentation de parallélisation à {current_workers} (taux de succès : {success_rate:.2f})")

        generate_summary(processed_count, active_count, all_ports, all_vulns)

        if not ips_to_scan:
            break

    generate_summary(processed_count, active_count, all_ports, all_vulns)
    if processed_count == total_ips:
        logger.info("Tous les scans sont terminés")
        event_queue.put({'event': 'progress', 'data': {'message': f"[{time.ctime()}] Tous les scans sont terminés"}})
    else:
        logger.info("Scan terminé partiellement")
        event_queue.put({'event': 'progress', 'data': {'message': f"[{time.ctime()}] Scan terminé partiellement"}})

# Routes Flask
@app.route('/')
def index():
    logger.info("Accès à la page d'accueil")
    return render_template('index.html')

@app.route('/events')
def events():
    def stream():
        logger.info("Client connecté au flux SSE")
        while True:
            try:
                event = event_queue.get(timeout=1)
                event_type = event['event']
                data = json.dumps(event['data'])
                yield f"event: {event_type}\ndata: {data}\n\n"
                event_queue.task_done()
            except Empty:
                yield f"event: ping\ndata: {time.time()}\n\n"
                time.sleep(0.5)

    return Response(stream(), mimetype='text/event-stream')


# noinspection PyUnresolvedReferences
@app.route('/start_scan/<scanner_type>/<strategy>')
def start_scan_endpoint(scanner_type, strategy):
    global stop_flag, scan_thread, nmap_scanner, netcat_scanner, current_scanner, active_processes
    proxy = request.args.get('proxy', None)
    logger.info(f"Requête HTTP pour démarrer le scan avec {scanner_type} et stratégie : {strategy}, proxy : {proxy}")

    global stop_flag, scan_thread, current_scanner, active_processes
    if scanner_type not in scanner_map:
        return f"Type de scanner inconnu : {scanner_type}", 400
    try:
        current_scanner = scanner_map[scanner_type]
        current_scanner.strategy = strategy  # Met à jour la stratégie
    except (ValueError, FileNotFoundError) as e:
        event_queue.put({'event': 'progress', 'data': {'message': f"[{time.ctime()}] Erreur : {str(e)}"}})
        return str(e), 400

    if scan_thread and scan_thread.is_alive():
        logger.info("Scan déjà en cours")
        event_queue.put({'event': 'progress', 'data': {'message': f"[{time.ctime()}] Un scan est déjà en cours !"}})
        return "Scan déjà en cours", 200

    stop_flag = False
    scan_thread = threading.Thread(target=scan_background)
    scan_thread.start()
    return f"Scan démarré avec {scanner_type} et stratégie {strategy}" + (f" et proxy {proxy}" if proxy else ""), 200

@app.route('/stop_scan')
def stop_scan_endpoint():
    global stop_flag
    logger.info("Requête HTTP pour arrêter le scan")
    stop_flag = True
    event_queue.put({'event': 'progress',
                     'data': {'message': f"[{time.ctime()}] Arrêt demandé. Attente de la fin du batch en cours..."}})
    return "Arrêt demandé", 200

if __name__ == "__main__":
    logger.info("Démarrage du serveur Flask sur 0.0.0.0:5000")
    try:
        app.run(host='0.0.0.0', port=5000, threaded=True)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)