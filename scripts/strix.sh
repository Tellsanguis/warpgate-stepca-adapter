#!/usr/bin/env bash
# Passe Strix (agents IA de test d'intrusion) en boîte blanche sur le code source de l'adaptateur.
# N'installe rien, ne lit aucune clé ailleurs que dans l'environnement.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${STRIX_SCAN_MODE:-standard}" # quick | standard | deep

die() { echo "strix.sh: $*" >&2; exit 1; }

command -v strix >/dev/null || die "strix n'est pas installé (pipx install strix-agent)"
command -v docker >/dev/null || die "Docker est requis (bac à sable de Strix)"
docker info >/dev/null 2>&1 || die "le démon Docker ne répond pas"
[ -n "${STRIX_LLM:-}" ] || die "STRIX_LLM n'est pas défini (modèle, ex. anthropic/<modèle>)"
if [ -z "${LLM_API_KEY:-}" ] && [ -z "${LLM_API_BASE:-}" ]; then
  die "définir LLM_API_KEY (service distant) ou LLM_API_BASE (modèle local, aucune donnée ne sort)"
fi
case "$MODE" in quick | standard | deep) ;; *) die "STRIX_SCAN_MODE invalide: $MODE" ;; esac

# Aucun secret dans l'arbre envoyé au modèle.
# (motif construit en deux morceaux pour que ce script ne se détecte pas lui-même)
if grep -rIlE --exclude-dir=.git --exclude-dir=strix_runs -e "-----BE""GIN [A-Z ]*PRIVATE KEY" "$ROOT" >/dev/null 2>&1; then
  die "une clé privée au format PEM est présente dans l'arbre: la retirer avant d'envoyer le code à un modèle"
fi

# Copie propre du code (sans caches ni journaux de scans précédents).
SRC="$(mktemp -d "${WORK_ROOT:-/tmp}/adapter-strix.XXXXXX")"
trap 'rm -rf "$SRC"' EXIT
tar -C "$ROOT" --exclude=.git --exclude=strix_runs --exclude=integration/.work -cf - . | tar -C "$SRC" -xf -

# La télémétrie de Strix est active par défaut (STRIX_TELEMETRY, v1.7.0): on la coupe.
export STRIX_TELEMETRY=0

# Strix enregistre sa configuration, clé d'API comprise, dans ~/.strix/cli-config.json (constaté en 1.7.0):
# HOME jetable, détruit à la sortie, pour que la clé ne persiste pas sur le disque.
STRIX_HOME="$(mktemp -d "${WORK_ROOT:-/tmp}/adapter-strix-home.XXXXXX")"
trap 'shred -u "$STRIX_HOME"/.strix/cli-config.json 2>/dev/null; rm -rf "$SRC" "$STRIX_HOME"' EXIT
export HOME="$STRIX_HOME"

INSTRUCTION="Périmètre strict: le code source de ce répertoire, un service Go qui émule l'API de signature SSH de Vault devant step-ca. \
Chercher: contournement d'authentification ou d'autorisation (jeton, rôle, principal), injection ou confusion de parsing dans la validation \
des requêtes, fuite de secret dans les journaux ou erreurs, faiblesse TLS, déni de service, mauvaise vérification du certificat renvoyé par la CA, \
condition de course. Ne cibler aucun hôte distant ni aucune autre machine. Ne produire aucune exploitation hors du bac à sable."

echo "Strix v$(strix --version 2>/dev/null | tr -dc '0-9.') | mode=$MODE | modèle=$STRIX_LLM | télémétrie coupée"
echo "Le code source est envoyé au fournisseur du modèle (sauf modèle local). Ctrl+C pour annuler dans 5 s."
sleep 5
# Les résultats (strix_runs/) vont dans STRIX_OUT, hors du dépôt si possible (ils contiennent des détails d'exploitation).
mkdir -p "${STRIX_OUT:-$ROOT}" && cd "${STRIX_OUT:-$ROOT}"
strix -n --target "$SRC" --scan-mode "$MODE" --instruction "$INSTRUCTION"
