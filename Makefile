# Makefile pour la gestion du projet de scanner réseau

# --- Variables de Configuration ---
# Utilise python3 par défaut. Peut être surchargé (ex: make PYTHON=python3.9 setup)
PYTHON := python3

# Nom du répertoire de l'environnement virtuel
VENV_DIR := .venv

# Chemin vers l'exécutable Python dans l'environnement virtuel
VENV_PYTHON := $(VENV_DIR)/bin/python

# Cible par défaut, exécutée quand on tape juste `make`
.DEFAULT_GOAL := help

# --- Cibles Principales ---

.PHONY: setup
setup: $(VENV_DIR)/bin/activate ## Crée l'environnement virtuel et installe les dépendances.
	@echo "Environnement virtuel '.venv' prêt et dépendances installées."

.PHONY: run
run: setup ## Démarre l'application Flask.
	@echo "Démarrage du serveur Flask sur http://localhost:5001..."
	@$(VENV_PYTHON) main.py

.PHONY: clean
clean: ## Supprime l'environnement virtuel et les fichiers temporaires.
	@echo "Nettoyage du projet..."
	rm -rf $(VENV_DIR)
	rm -f *.pyc
	rm -rf __pycache__
	@echo "Environnement virtuel et fichiers temporaires supprimés."

.PHONY: help
help: ## Affiche ce message d'aide.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

# --- Cibles Internes (logique de construction) ---

# Cette règle crée l'environnement virtuel et installe les dépendances.
# Elle ne s'exécute que si le répertoire .venv n'existe pas ou si requirements.txt a été modifié.
$(VENV_DIR)/bin/activate: requirements.txt
	@echo "Création de l'environnement virtuel dans '$(VENV_DIR)'..."
	$(PYTHON) -m venv $(VENV_DIR)
	@echo "Mise à jour de pip..."
	@$(VENV_PYTHON) -m pip install --upgrade pip
	@echo "Installation des dépendances depuis requirements.txt..."
	@$(VENV_PYTHON) -m pip install -r requirements.txt
	@touch $(VENV_DIR)/bin/activate # Met à jour le timestamp pour que `make` sache que la cible est à jour
