# ~~Nmap Scanner Flask~~ DEPRECATED

Scanner Nmap parallélisé avec interface Flask et logs WebSocket.

## Features

- Scans parallèles (adaptatifs).
- Web UI : start/stop/shutdown.
- Logs live dans le browser.
- `.env` pour `IP_RANGES`.

## Setup

1. `pip install flask flask-socketio eventlet python-dotenv`
2. `.env` : `IP_RANGES=56.17.128.0/21,56.20.135.0/24,...`
3. `templates/index.html` (voir code).
4. `sudo` sans mdp pour `nmap` et `shutdown`.

## Run

```bash
python3 main.py
```

Ouvre `http://localhost:5000`.

## Output

- `active-ips.txt` : IPs actives.
- `summary.txt` : Stats.
- `progress.txt` : Progression.

## Config

- `.env` : IPs.
- Script : `MAX_WORKERS`, timeout.

## Notes

- Autorisation réseau requise.
- Teste localement d’abord.

