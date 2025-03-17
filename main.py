import ipaddress
import logging
import os
import subprocess
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

# Charger le fichier .env
load_dotenv()

# Configuration Flask
app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')


# Configuration des logs pour WebSocket
class WebSocketHandler(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        socketio.emit('log', {'message': log_entry}, namespace='/scan')


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger()
logger.addHandler(WebSocketHandler())

# Fichiers
ACTIVE_IPS_FILE = "active_ips.txt"
PROGRESS_FILE = "progress_ips.txt"
RESULTS_DIR = "scan_results"
SUMMARY_FILE = "summary.txt"

# Liste des plages d'IP à scanner
IP_RANGES = os.getenv("IP_RANGES", "").split(",")

# Paramètres de parallélisation
INITIAL_MAX_WORKERS = 1  # 10
MIN_WORKERS = 1  # 2
MAX_WORKERS = 20

# Créer le dossier de résultats
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

# Variables globales
stop_flag = False
success_rate = 0.0
scan_thread = None


# Générer toutes les adresses IP
def generate_all_ips(ranges):
    all_ips = []
    for cidr in ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            all_ips.extend([str(ip) for ip in network.hosts()])
        except ValueError as e:
            logger.error(f"Erreur dans la plage {cidr} : {e}")
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


# Parser la sortie de Nmap pour extraire ports, OS, versions et vulnérabilités
def parse_nmap_output(output_file):
    if not os.path.exists(output_file):
        return False, "", [], None, {}, []
    try:
        with open(output_file, "r") as f:
            content = f.read()
            ports = []
            os_info = None
            versions = {}
            vulns = []

            for line in content.splitlines():
                # Ports ouverts
                if "open" in line and "/" in line:
                    try:
                        port = int(line.split("/")[0].strip())
                        ports.append(port)
                    except ValueError:
                        continue
                # Détection OS
                if "OS details" in line:
                    os_info = line.split("OS details: ")[1].strip()
                # Versions des services
                if "open" in line and "VERSION" in line:
                    parts = line.split()
                    port = int(parts[0].split("/")[0])
                    version = " ".join(parts[2:])
                    versions[port] = version
                # Vulnérabilités NSE
                if "VULNERABLE" in line:
                    vulns.append(line.strip())

            return len(ports) > 0, content, ports, os_info, versions, vulns
    except Exception as e:
        logger.error(f"Erreur lors de l’analyse de {output_file} : {e}")
        return False, "", [], None, {}, []


# Sauvegarder la sortie complète d'une IP active
def save_active_ip(ip, output, os_info, versions, vulns):
    try:
        with open(ACTIVE_IPS_FILE, "a") as f:
            f.write(f"\n{'=' * 50}\n")
            f.write(f"Scan results for {ip} ({time.ctime()}):\n")
            f.write(f"{'=' * 50}\n")
            f.write(f"OS: {os_info if os_info else 'Non détecté'}\n")
            f.write("Service Versions:\n")
            for port, version in versions.items():
                f.write(f"  Port {port}: {version}\n")
            f.write("Vulnérabilités détectées:\n")
            for vuln in vulns:
                f.write(f"  {vuln}\n")
            f.write(f"Full Nmap Output:\n{output}\n")
    except Exception as e:
        logger.error(f"Erreur lors de l'écriture dans {ACTIVE_IPS_FILE} : {e}")


# Scanner une adresse IP avec Nmap (limité aux 1000 premiers ports)
def scan_ip(ip):
    global stop_flag
    if stop_flag:
        return ip, False, None, [], None, None

    output_file = os.path.join(RESULTS_DIR, f"scan_{ip}.txt")
    logger.info(f"Début du scan de {ip}")
    socketio.emit('progress', {'message': f"Scanning {ip}..."}, namespace='/scan')
    try:
        # Commande Nmap modifiée : scan des ports 1-1000 uniquement
        cmd = ["sudo", "nmap", "-A", "-O", "-sS", "-f", "--script", "vuln", "-p", "1-1000", ip, "-oN", output_file]
        subprocess.run(cmd, check=True, timeout=600)
        logger.info(f"Scan de {ip} terminé avec succès")

        # Analyse des résultats
        is_active, output, ports, os_info, versions, vulns = parse_nmap_output(output_file)
        if is_active:
            save_active_ip(ip, output, os_info, versions, vulns)
            logger.info(f"{ip} est active (ports: {ports}, OS: {os_info}, Vulns: {len(vulns)})")
            socketio.emit('progress', {'message': f"{ip} est active !"}, namespace='/scan')
        else:
            logger.info(f"{ip} n’a pas de ports ouverts")

        return ip, True, None, ports, os_info, vulns
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur lors du scan de {ip} : {e}")
        return ip, False, str(e), [], None, None
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout lors du scan de {ip}")
        return ip, False, "Timeout", [], None, None
    except Exception as e:
        logger.error(f"Erreur inattendue lors du scan de {ip} : {e}")
        return ip, False, str(e), [], None, None


# Générer un rapport synthétique
def generate_summary(total_scanned, active_count, all_ports, all_vulns):
    try:
        port_counter = Counter(all_ports)
        vuln_counter = Counter(all_vulns)
        with open(SUMMARY_FILE, "a") as f:
            f.write(f"\n{'-' * 50}\n")
            f.write(f"Résumé du scan ({time.ctime()}):\n")
            f.write(f"IPs scannées : {total_scanned}\n")
            f.write(f"IPs actives (avec ports ouverts) : {active_count}\n")
            f.write("\nPorts les plus fréquents détectés :\n")
            if port_counter:
                for port, count in port_counter.most_common(5):
                    f.write(f"Port {port} : {count} IPs\n")
            else:
                f.write("Aucun port détecté.\n")
            f.write("\nVulnérabilités les plus fréquentes :\n")
            if vuln_counter:
                for vuln, count in vuln_counter.most_common(5):
                    f.write(f"{vuln} : {count} IPs\n")
            else:
                f.write("Aucune vulnérabilité détectée.\n")
            f.write(f"{'-' * 50}\n")
    except Exception as e:
        logger.error(f"Erreur lors de l'écriture dans {SUMMARY_FILE} : {e}")


# Fonction de scan en arrière-plan
def scan_background():
    global stop_flag, success_rate, scan_thread
    logger.info("Démarrage du programme")

    all_ips = generate_all_ips(IP_RANGES)
    total_ips = len(all_ips)
    if total_ips == 0:
        logger.error("Aucune IP valide générée.")
        socketio.emit('progress', {'message': "Erreur : Aucune IP à scanner."}, namespace='/scan')
        return
    logger.info(f"Total des IPs à scanner : {total_ips}")

    completed_ips = load_progress()
    ips_to_scan = [ip for ip in all_ips if ip not in completed_ips]
    remaining_ips = len(ips_to_scan)
    if remaining_ips == 0:
        logger.info("Toutes les IPs ont déjà été scannées.")
        socketio.emit('progress', {'message': "Toutes les IPs ont déjà été scannées !"}, namespace='/scan')
        generate_summary(total_ips, 0, [], [])
        return

    socketio.emit('progress', {'message': f"IPs restantes à scanner : {remaining_ips}"}, namespace='/scan')

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
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            future_to_ip = {executor.submit(scan_ip, ip): ip for ip in batch}

            for future in as_completed(future_to_ip):
                ip = future_to_ip.pop(future)
                processed_count += 1

                try:
                    ip, success, error, ports, os_info, vulns = future.result()
                    if success:
                        success_count += 1
                        save_progress(ip)
                        if ports:
                            active_count += 1
                            all_ports.extend(ports)
                            all_vulns.extend(vulns)
                    socketio.emit('progress', {
                        'message': f"Progression : {processed_count}/{total_ips} ({(processed_count / total_ips) * 100:.2f}%)"
                    }, namespace='/scan')
                except Exception as e:
                    logger.error(f"Erreur inattendue pour {ip} : {e}")
                    socketio.emit('progress', {'message': f"Erreur pour {ip} : {e}"}, namespace='/scan')

        success_rate = success_count / batch_size if batch_size > 0 else 0
        if success_rate < 0.7 and current_workers > MIN_WORKERS:
            current_workers -= 2
            logger.info(f"Réduction de parallélisation à {current_workers} (taux de succès : {success_rate:.2f})")
        elif success_rate > 0.9 and current_workers < MAX_WORKERS:
            current_workers += 2
            logger.info(f"Augmentation de parallélisation à {current_workers} (taux de succès : {success_rate:.2f})")

        generate_summary(processed_count, active_count, all_ports, all_vulns)

        if not ips_to_scan:
            break

    generate_summary(processed_count, active_count, all_ports, all_vulns)
    if processed_count == total_ips:
        logger.info("Tous les scans sont terminés")
        socketio.emit('progress', {'message': "Tous les scans sont terminés !"}, namespace='/scan')
    else:
        logger.info("Scan terminé partiellement")
        socketio.emit('progress', {'message': "Scan terminé partiellement. Relance pour continuer."}, namespace='/scan')


# Routes Flask
@app.route('/')
def index():
    return render_template('index.html')


# Événements WebSocket
@socketio.on('start_scan', namespace='/scan')
def start_scan():
    global stop_flag, scan_thread
    # noinspection PyUnresolvedReferences
    if scan_thread and scan_thread.is_alive():
        emit('progress', {'message': "Un scan est déjà en cours !"})
        return
    stop_flag = False
    scan_thread = threading.Thread(target=scan_background)
    scan_thread.start()
    emit('progress', {'message': "Scan démarré."})


@socketio.on('stop_scan', namespace='/scan')
def stop_scan():
    global stop_flag
    stop_flag = True
    emit('progress', {'message': "Arrêt demandé. Attente de la fin du batch en cours..."})


@socketio.on('shutdown', namespace='/scan')
def shutdown():
    global stop_flag
    stop_flag = True
    emit('progress', {'message': "Arrêt de la machine demandé. Extinction dans 2 secondes..."})
    time.sleep(2)
    os.system("sudo shutdown -h now")


if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000)
