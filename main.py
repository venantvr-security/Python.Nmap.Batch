import ipaddress
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from queue import Queue, Empty

import toml
from dotenv import load_dotenv
from flask import Flask, render_template, Response, request, jsonify
from psutil import NoSuchProcess, AccessDenied

# noinspection PyUnresolvedReferences
from scanners.CurlScanner import CurlScanner
# noinspection PyUnresolvedReferences
from scanners.Hping3Scanner import Hping3Scanner
# noinspection PyUnresolvedReferences
from scanners.MasscanScanner import MasscanScanner
# noinspection PyUnresolvedReferences
from scanners.NetcatScanner import NetcatScanner
# noinspection PyUnresolvedReferences
from scanners.NmapScanner import NmapScanner
# noinspection PyUnresolvedReferences
from scanners.Pcap2 import Pcap2
# noinspection PyUnresolvedReferences
from scanners.ScapyScanner import ScapyScanner

# --- Configuration Robuste des Chemins ---
# Chemin absolu de la racine du projet (là où se trouve ce script)
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Charger la configuration depuis config.toml
CONFIG_FILE = os.path.join(APP_ROOT, 'config.toml')
with open(CONFIG_FILE, 'r') as f:
    config = toml.load(f)

# Construire les chemins absolus à partir de la racine de l'application
PATHS = {
    key: os.path.join(APP_ROOT, path) for key, path in config['paths'].items()
}

# Exposer les chemins nécessaires aux autres modules via les variables d'environnement
os.environ['PCAP_TEMPLATES_DIR'] = PATHS['pcap_templates_dir']

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

# Liste des plages d'IP à scanner
IP_RANGES = os.getenv("IP_RANGES", "30.31.32.33").split(",")
logger.info(f"Plages IP chargées : {IP_RANGES}")

# Paramètres de parallélisation
INITIAL_MAX_WORKERS = 3
MIN_WORKERS = 3
MAX_WORKERS = 10

# Variables globales
stop_flag = False
success_rate = 0.0
scan_thread = None
active_processes = []
event_queue = Queue()
tor_enabled = False
tor_identity_change_freq = 0

# Initialisation des scanners
import yaml

# Chemin du fichier de définition
DEFINITION_FILE = os.path.join(str(PATHS['strategies_dir']), "definitions.yaml")


def parse_nmap_ports(port_string):
    """
    Parse une chaîne de ports au format Nmap (ex. "22,80,100-200,443") et renvoie une liste de ports.

    Args:
        port_string (str): Chaîne de ports séparés par des virgules, incluant des plages avec tirets.

    Returns:
        list: Liste complète des numéros de ports.

    Raises:
        ValueError: Si la syntaxe est invalide ou les ports hors limites (1-65535).
    """
    ports = []

    # Séparer les éléments par des virgules
    items = port_string.split(',')

    for item in items:
        item = item.strip()  # Supprimer les espaces éventuels

        # Vérifier si c'est une plage (contient un tiret)
        if '-' in item:
            try:
                start, end = map(int, item.split('-'))
                # Vérifier que les valeurs sont valides
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError(f"Ports hors limites (1-65535) dans la plage {item}")
                if start > end:
                    raise ValueError(f"Plage invalide dans {item}: début > fin")
                # Ajouter tous les ports de la plage
                ports.extend(range(start, end + 1))
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Syntaxe invalide dans la plage {item}: nombres attendus")
                raise e
        else:
            # Cas d'un port unique
            try:
                port = int(item)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port hors limites (1-65535): {port}")
                ports.append(port)
            except ValueError:
                raise ValueError(f"Syntaxe invalide pour le port {item}: nombre attendu")

    # Supprimer les doublons et trier (optionnel, selon tes besoins)
    ports = sorted(list(set(ports)))
    return ports


def get_first_strategy(yaml_file):
    """Lit un fichier YAML et renvoie le nom de la première stratégie sous 'strategy'."""
    try:
        with open(yaml_file, 'r') as file:
            data = yaml.safe_load(file)
            # Récupère directement les stratégies sous 'strategy'
            strategies = data.get('strategies', {})
            # Renvoie la première clé sous 'strategy'
            return next(iter(strategies.keys())) if strategies else None
    except (FileNotFoundError, yaml.YAMLError) as e:
        print(f"Erreur lors de la lecture de {yaml_file}: {e}")
        return None


def load_scanner_definitions(definition_file):
    """Charge les définitions des scanners depuis definitions.yaml."""
    try:
        with open(definition_file, 'r') as file:
            data = yaml.safe_load(file)
            return data.get('scanners', {})
    except (FileNotFoundError, yaml.YAMLError) as e:
        print(f"Erreur lors de la lecture de {definition_file}: {e}")
        return {}


def build_scanners_config_and_map(strategies_dir=PATHS['strategies_dir'], definition_file=DEFINITION_FILE):
    """Construit dynamiquement scanners_config et scanner_map."""
    scanners_config = []
    scanners = {}
    scanner_map = {}

    # Charge les définitions des scanners
    scanner_definitions = load_scanner_definitions(definition_file)

    if not scanner_definitions:
        print("Aucune définition de scanner trouvée.")
        return scanners_config, scanner_map

    # Vérifie les fichiers dans le répertoire strategies/
    available_files = {f for f in os.listdir(str(strategies_dir)) if f.endswith('.yaml') and f != 'definitions.yaml'}

    # Construit scanners_config et initialise les scanners
    for scanner_key, config in scanner_definitions.items():
        class_name = config.get('class')
        file_name = config.get('file')

        if not class_name or not file_name:
            print(f"Configuration invalide pour {scanner_key}: 'class' ou 'file' manquant.")
            continue

        full_file_path = os.path.join(str(strategies_dir), str(file_name))
        if file_name in available_files:
            scanners_config.append((class_name, full_file_path))
            strategy = get_first_strategy(full_file_path)
            if strategy:
                # Instancie le scanner
                scanners[class_name] = globals()[class_name](
                    strategy=strategy,
                    process_manager=active_processes,
                    yaml_file=full_file_path
                )
                # Ajoute au scanner_map avec la clé (ex. "nmap")
                scanner_map[scanner_key] = scanners[class_name]
            else:
                print(f"Aucune stratégie trouvée pour {class_name} dans {full_file_path}")
        else:
            print(f"Fichier {file_name} pour {class_name} non trouvé dans {strategies_dir}")

    return scanners_config, scanner_map


# Exemple d'utilisation
scanners_config, scanner_map = build_scanners_config_and_map()
print("Scanners configurés dynamiquement :", scanners_config)
print("Scanner map :", {k: v.__class__.__name__ for k, v in scanner_map.items()})

# Initialisation dynamique des scanners
scanners = {}
for scanner_class, yaml_file in scanners_config:
    strategy = get_first_strategy(yaml_file)
    if strategy:
        # Suppose que les classes comme NmapScanner, etc., sont déjà importées
        scanners[scanner_class] = globals()[scanner_class](
            strategy=strategy,
            process_manager=active_processes,
            yaml_file=yaml_file
        )
    else:
        print(f"Aucune stratégie trouvée pour {scanner_class} dans {yaml_file}")

current_scanner = list(scanner_map.values())[0]  # nmap_scanner


# Gestion de l'arrêt propre
# noinspection PyUnresolvedReferences,PyUnusedLocal
def signal_handler(sig, frame):
    global stop_flag
    stop_flag = True
    logger.info("Signal d'arrêt reçu (Ctrl+C), arrêt en cours...")
    for proc in active_processes:
        if proc.poll() is None:
            proc.kill()  # Force la terminaison
            logger.info(f"Processus {proc.pid} tué")
    if scan_thread and scan_thread.is_alive():
        scan_thread.join(timeout=5)
    logger.info("Serveur arrêté proprement")
    sys.exit(0)


# Chemin du fichier ports.yaml
PORTS_FILE = os.path.join(str(PATHS['strategies_dir']), "ports.yaml")


# Parser pour les ports Nmap
def parse_nmap_ports(port_string):
    ports = []
    items = port_string.split(',')
    for item in items:
        item = item.strip()
        if '-' in item:
            start, end = map(int, item.split('-'))
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Ports hors limites (1-65535) dans la plage {item}")
            if start > end:
                raise ValueError(f"Plage invalide dans {item}: début > fin")
            ports.extend(range(start, end + 1))
        else:
            port = int(item)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port hors limites (1-65535): {port}")
            ports.append(port)
    return sorted(list(set(ports)))


# Nouvelle route pour les ports
@app.route('/api/ports', methods=['GET'])
def get_ports():
    """Renvoie les lignes brutes de ports à partir de strategies/ports.yaml."""
    try:
        with open(PORTS_FILE, 'r') as file:
            data = yaml.safe_load(file)
            port_entries = data.get('ports', [])
            return jsonify({"ports": port_entries})
    except FileNotFoundError:
        logger.error(f"Fichier {PORTS_FILE} non trouvé")
        return jsonify({"error": f"Fichier {PORTS_FILE} non trouvé"}), 404
    except yaml.YAMLError as e:
        logger.error(f"Erreur de syntaxe dans {PORTS_FILE} : {e}")
        return jsonify({"error": f"Erreur de syntaxe dans {PORTS_FILE}"}), 500
    except Exception as e:
        logger.error(f"Erreur inattendue : {e}")
        return jsonify({"error": "Erreur inattendue"}), 500


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
    progress_file_path = str(PATHS['progress_file'])
    if os.path.exists(progress_file_path):
        try:
            with open(progress_file_path, "r") as f:
                return set(line.strip() for line in f if line.strip())
        except Exception as e:
            logger.error(f"Erreur lors de la lecture de {progress_file_path} : {e}")
            return set()
    return set()


# Sauvegarder une IP terminée
def save_progress(ip):
    progress_file_path = str(PATHS['progress_file'])
    try:
        with open(progress_file_path, "a") as f:
            f.write(f"{ip}\n")
    except Exception as e:
        logger.error(f"Erreur lors de l'écriture dans {progress_file_path} : {e}")


# Sauvegarder les résultats dans results/<type_de_script>/<stratégie>/<ip>.json
def save_scan_result(scanner_type, strategy, ip, scan_result):
    base_dir = os.path.join(str(PATHS['results_dir']), str(scanner_type), str(strategy))
    os.makedirs(base_dir, exist_ok=True)  # Crée les répertoires si nécessaire
    result_file = os.path.join(str(base_dir), f"{ip}.json")
    try:
        with open(result_file, "w") as f:
            # noinspection PyTypeChecker
            json.dump(scan_result, f, indent=2)
        logger.info(f"Résultat du scan sauvegardé dans {result_file}")
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde du résultat dans {result_file} : {e}")


# Nouvelle route pour récupérer les stratégies
@app.route('/strategies/get/<scanner_type>')
def get_strategies(scanner_type):
    # Dictionnaire des scanners et leurs fichiers YAML
    scanner_files = {
        "nmap": "nmap-strategies.yaml",
        "netcat": "netcat-strategies.yaml",
        "scapy": "scapy-strategies.yaml",
        "masscan": "masscan-strategies.yaml",
        "hping3": "hping3-strategies.yaml",
        "curl": "curl-strategies.yaml",
    }

    if scanner_type not in scanner_files:
        return jsonify(
            {"error": f"Type de scanner inconnu : {scanner_type}. Options valides : {list(scanner_files.keys())}"}), 400

    yaml_file = os.path.join(str(PATHS['strategies_dir']), str(scanner_files[scanner_type]))
    try:
        with open(yaml_file, 'r') as file:
            data = yaml.safe_load(file)
            if not data or 'strategies' not in data:
                return jsonify({"error": f"Le fichier {yaml_file} doit contenir une clé 'strategies'"}), 400
            strategies = list(data['strategies'].keys())
        return jsonify({"strategies": strategies})
    except FileNotFoundError:
        return jsonify({"error": f"Fichier {yaml_file} non trouvé"}), 404
    except yaml.YAMLError as e:
        return jsonify({"error": f"Erreur de syntaxe dans {yaml_file} : {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Erreur inattendue : {str(e)}"}), 500


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
        event_queue.put(
            {'event': 'progress', 'data': {'message': f"[{time.ctime()}] Toutes les IPs ont déjà été scannées"}})
        return

    event_queue.put(
        {'event': 'progress', 'data': {'message': f"[{time.ctime()}] IPs restantes à scanner : {remaining_ips}"}})

    current_workers = INITIAL_MAX_WORKERS
    processed_count = len(completed_ips)
    active_count = 0
    all_ports = []
    all_vulns = []

    # Récupérer le type de scanner pour la sauvegarde
    scanner_type = [key for key, value in scanner_map.items() if value == current_scanner][0]
    strategy = current_scanner.strategy

    while ips_to_scan and not stop_flag:
        batch_size = min(current_workers, len(ips_to_scan))
        batch = ips_to_scan[:batch_size]
        ips_to_scan = ips_to_scan[batch_size:]

        success_count = 0
        logger.info(f"Début du batch avec {batch_size} IPs : {batch}")
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            future_to_ip = {
                executor.submit(current_scanner.scan, ip, str(uuid.uuid4()), event_queue, lambda: stop_flag): ip for ip
                in batch}

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                processed_count += 1
                try:
                    ip, success, error, details, extra = future.result()
                    # Préparer les données pour la sauvegarde
                    scan_result = {
                        "ip": ip,
                        "success": success,
                        "error": error,
                        "details": details,
                        "extra": extra,
                        "timestamp": time.ctime()
                    }
                    # Sauvegarder le résultat dans results/<type>/<stratégie>/<ip>.json
                    save_scan_result(scanner_type, strategy, ip, scan_result)

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
                    event_queue.put(
                        {'event': 'progress', 'data': {'message': f"[{time.ctime()}] Erreur pour {ip} : {e}"}})

        success_rate = success_count / batch_size if batch_size > 0 else 0
        if success_rate < 0.7 and current_workers > MIN_WORKERS:
            current_workers -= 1
            logger.info(f"Réduction de parallélisation à {current_workers} (taux de succès : {success_rate:.2f})")
        elif success_rate > 0.9 and current_workers < MAX_WORKERS:
            current_workers += 1
            logger.info(f"Augmentation de parallélisation à {current_workers} (taux de succès : {success_rate:.2f})")

        if not ips_to_scan:
            break

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
@app.route('/scan/start/<scanner_type>/<strategy>')
def start_scan_endpoint(scanner_type, strategy):
    global stop_flag, scan_thread, current_scanner, active_processes, IP_RANGES
    proxy = request.args.get('proxy', None)
    ports = request.args.get('ports', None)
    ip_ranges = request.args.get('ip_ranges', None)
    logger.info(
        f"Requête HTTP pour démarrer le scan avec {scanner_type} et stratégie : {strategy}, ports : {ports}, ip_ranges : {ip_ranges}, proxy : {proxy}")

    if scanner_type not in scanner_map:
        return f"Type de scanner inconnu : {scanner_type}", 400

    if not ports:
        event_queue.put({'event': 'progress', 'data': {'message': f"[{time.ctime()}] Erreur : Aucun port spécifié"}})
        return "Aucun port spécifié", 400

    # Mettre à jour IP_RANGES si fourni dans la requête
    if ip_ranges:
        IP_RANGES = ip_ranges.split(",")
        logger.info(f"IP ranges mises à jour : {IP_RANGES}")

    try:
        current_scanner = scanner_map[scanner_type]
        current_scanner.strategy = strategy
        current_scanner.ports = ports
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
    return f"Scan démarré avec {scanner_type} et stratégie {strategy}" + (f" et ports {ports}" if ports else "") + (
        f" et ip_ranges {ip_ranges}" if ip_ranges else "") + (f" et proxy {proxy}" if proxy else ""), 200


def load_and_validate_scanner_definitions(definition_file=DEFINITION_FILE, strategies_dir=PATHS['strategies_dir']):
    """Charge et valide dynamiquement les définitions des scanners depuis definitions.yaml."""
    try:
        with open(definition_file, 'r') as file:
            data = yaml.safe_load(file)
            scanner_definitions = data.get('scanners', {})
    except (FileNotFoundError, yaml.YAMLError) as e:
        logger.error(f"Erreur lors de la lecture de {definition_file}: {e}")
        return {}

    available_files = {f for f in os.listdir(str(strategies_dir)) if f.endswith('.yaml') and f != 'definitions.yaml'}
    valid_definitions = {}
    for scanner_key, config in scanner_definitions.items():
        class_name = config.get('class')
        file_name = config.get('file')
        if not class_name or not file_name:
            logger.warning(f"Configuration invalide pour {scanner_key}: 'class' ou 'file' manquant.")
            continue
        if file_name in available_files:
            valid_definitions[scanner_key] = config
        else:
            logger.warning(f"Fichier {file_name} pour {scanner_key} non trouvé dans {strategies_dir}, ignoré.")
    return valid_definitions


# Route API pour les scanners (déjà présente)
@app.route('/api/scanners', methods=['GET'])
def get_scanners():
    """Renvoie la liste des scanners disponibles avec leurs stratégies."""
    scanners_data = []

    scanner_definitions = load_and_validate_scanner_definitions()
    for scanner_key, scanner_instance in scanner_map.items():
        yaml_file = os.path.join(str(PATHS['strategies_dir']), str(scanner_definitions[scanner_key]['file']))
        metadata_file = str(yaml_file).replace('.yaml', '-metadata.yaml')

        try:
            with open(yaml_file, 'r') as file:
                data = yaml.safe_load(file)

            # Charger metadata
            metadata = {}
            try:
                with open(metadata_file, 'r') as f:
                    metadata = yaml.safe_load(f) or {}
            except FileNotFoundError:
                pass

            # Enrichir avec metadata
            strategies_with_metadata = [
                {
                    "name": name,
                    "complexity": metadata.get(name, {}).get("complexity", 1),
                    "type": metadata.get(name, {}).get("type", "basic")
                }
                for name in data.get('strategies', {}).keys()
            ]
            strategies_with_metadata.sort(key=lambda x: x['complexity'])

        except Exception as e:
            logger.error(f"Erreur lors de la lecture de {yaml_file} : {e}")
            strategies_with_metadata = []

        scanners_data.append({
            "name": scanner_key,
            "class": f"btn-{scanner_key}",
            "strategies": strategies_with_metadata
        })

    return jsonify(scanners_data)


@app.route('/scanner/info/get/<scanner_type>')
def get_scanner_info(scanner_type):
    scanner_files = {
        "nmap": "NMAP.md",
        "netcat": "NETCAT.md",
        "scapy": "SCAPY.md",
        "masscan": "MASSCAN.md",
        "hping3": "HPING3.md",
        "curl": "CURL.md",
        "pcap2": "PCAP2.md",
    }

    if scanner_type not in scanner_files:
        return jsonify({"error": f"Type de scanner inconnu : {scanner_type}"}), 400

    md_file = os.path.join(str(PATHS['docs_dir']), str(scanner_files[scanner_type]))
    try:
        with open(md_file, 'r', encoding='utf-8') as file:
            content = file.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": f"Fichier {md_file} non trouvé"}), 404
    except Exception as e:
        return jsonify({"error": f"Erreur inattendue : {str(e)}"}), 500


@app.route('/scan/stop')
def stop_scan_endpoint():
    global stop_flag
    logger.info("Requête HTTP pour arrêter le scan")
    stop_flag = True
    event_queue.put({'event': 'progress',
                     'data': {'message': f"[{time.ctime()}] Arrêt demandé. Attente de la fin du batch en cours..."}})
    return "Arrêt demandé", 200


@app.route('/progress/reset', methods=['POST'])
def reset_progress_endpoint():
    progress_file_path = str(PATHS['progress_file'])
    logger.info("Requête HTTP pour réinitialiser le fichier de progression")
    try:
        if os.path.exists(progress_file_path):
            os.remove(progress_file_path)
            logger.info(f"Fichier {progress_file_path} supprimé avec succès")
            event_queue.put(
                {'event': 'progress', 'data': {'message': f"[{time.ctime()}] Fichier de progression réinitialisé"}})
            return "Fichier de progression réinitialisé", 200
        else:
            logger.info(f"Le fichier {progress_file_path} n'existe pas")
            return "Aucun fichier de progression à supprimer", 200
    except Exception as e:
        logger.error(f"Erreur lors de la suppression de {progress_file_path} : {e}")
        event_queue.put(
            {'event': 'progress', 'data': {'message': f"[{time.ctime()}] Erreur lors de la réinitialisation : {e}"}})
        return f"Erreur : {str(e)}", 500


@app.route('/api/docs/list', methods=['GET'])
def list_docs():
    """Liste les fichiers .md de la documentation."""
    docs_dir = str(PATHS['docs_dir'])
    try:
        files = [f for f in os.listdir(docs_dir) if f.endswith('.md') and f != 'README.md']
        return jsonify(sorted(files))
    except FileNotFoundError:
        logger.error(f"Le répertoire de documentation {docs_dir} est introuvable.")
        return jsonify({"error": "Répertoire docs non trouvé"}), 404


@app.route('/api/docs/content/<filename>', methods=['GET'])
def get_doc_content(filename):
    """Renvoie le contenu d'un fichier de documentation."""
    docs_dir = str(PATHS['docs_dir'])
    # Sécurité : Assurez-vous que le nom de fichier ne contient pas de ".." pour éviter le path traversal
    if '..' in filename or not filename.endswith('.md'):
        return jsonify({"error": "Nom de fichier invalide"}), 400
    try:
        file_path = os.path.join(str(docs_dir), str(filename))
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return jsonify({"title": filename, "content": content})
    except FileNotFoundError:
        return jsonify({"error": f"Fichier {filename} non trouvé"}), 404


def check_tor_status():
    try:
        req = urllib.request.Request('https://check.torproject.org/api/ip')
        req.add_header('User-Agent', 'Mozilla/5.0')
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            return data.get('IsTor', False)
    except:
        return False


@app.route('/api/tor/status', methods=['GET'])
def get_tor_status():
    return jsonify({"tor_enabled": check_tor_status()})


@app.route('/api/tor/identity/change', methods=['POST'])
def change_tor_identity():
    try:
        from stem import Signal
        from stem.control import Controller

        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            return jsonify({"success": True, "message": "Identité TOR changée"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/tor/identity/frequency', methods=['POST'])
def set_tor_identity_frequency():
    global tor_identity_change_freq
    data = request.get_json()
    tor_identity_change_freq = data.get('frequency', 0)
    return jsonify({"success": True, "frequency": tor_identity_change_freq})


@app.route('/api/ip-ranges', methods=['GET'])
def get_ip_ranges():
    """Retourne les IP ranges depuis .env comme placeholder."""
    default_ip_ranges = os.getenv("IP_RANGES", "30.31.32.33")
    return jsonify({"ip_ranges": default_ip_ranges})


@app.route('/processes')
def processes():
    return render_template('processes.html')


@app.route('/api/processes', methods=['GET'])
def get_processes():
    """Retourne la liste des processus actifs avec métadonnées."""
    processes_list = []
    for proc in active_processes:
        try:
            import psutil

            p = psutil.Process(proc.pid)
            is_running = proc.poll() is None

            # Extraire metadata si disponible (scanner, strategy, ip)
            cmdline = p.cmdline()
            scanner = "unknown"
            strategy = "unknown"
            ip = "unknown"

            # Essayer de détecter le scanner depuis la cmdline
            if cmdline:
                cmd_str = " ".join(cmdline)
                if "nmap" in cmd_str.lower():
                    scanner = "nmap"
                elif "masscan" in cmd_str.lower():
                    scanner = "masscan"
                elif "nc" in cmd_str or "netcat" in cmd_str.lower():
                    scanner = "netcat"
                elif "hping" in cmd_str.lower():
                    scanner = "hping3"
                elif "curl" in cmd_str.lower():
                    scanner = "curl"
                elif "scapy" in cmd_str.lower():
                    scanner = "scapy"

            start_time = datetime.fromtimestamp(p.create_time())
            uptime = (datetime.now() - start_time).total_seconds()

            processes_list.append({
                "id": f"{scanner}_{proc.pid}",
                "pid": proc.pid,
                "scanner": scanner,
                "strategy": strategy,
                "ip": ip,
                "thread_id": "unknown",
                "status": "running" if is_running else "terminated",
                "start_time": start_time.isoformat(),
                "cpu_percent": p.cpu_percent(interval=0.1) if is_running else 0,
                "memory_mb": p.memory_info().rss / 1024 / 1024 if is_running else 0,
                "uptime_seconds": uptime,
                "cmdline": " ".join(cmdline[:5]) if cmdline else "N/A"
            })
        except (NoSuchProcess, AccessDenied, AttributeError):
            pass
    return jsonify(processes_list)


@app.route('/api/processes/<int:pid>/kill', methods=['POST'])
def kill_process(pid):
    """Tue un processus spécifique."""
    for proc in active_processes:
        if proc.pid == pid:
            try:
                proc.kill()
                return jsonify({"success": True, "message": f"Process {pid} killed"})
            except:
                return jsonify({"success": False, "error": "Failed to kill process"}), 500
    return jsonify({"success": False, "error": "Process not found"}), 404


if __name__ == "__main__":
    logger.info("Démarrage du serveur Flask sur 0.0.0.0:5000")
    try:
        app.run(host='0.0.0.0', port=5001, threaded=True)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
