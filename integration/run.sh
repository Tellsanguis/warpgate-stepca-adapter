#!/usr/bin/env bash
# Intégration: un vrai step-ca éphémère (image de production épinglée), l'image de l'adaptateur, un réseau Docker interne.
# Tout est jetable. Aucune connexion à la CA de production. Voir integration/README.md.
set -euo pipefail

: "${STEPCA_IMAGE:?}" "${GO_IMAGE:?}" "${UID_GID:?}" "${CACHE:?}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$$"
NET="adapter-it-net-$RUN"
CA="it-stepca"
AD="it-adapter"
WORK="$(mktemp -d "${WORK_ROOT:-/tmp}/adapter-it.XXXXXX")"
IMAGE="${IMAGE:-warpgate-stepca-adapter:dev}"
DEMO="${DEMO:-0}"                      # 1 = environnement de démonstration laissé en marche (make demo)
HP="${DEMO_HTTP_PORT:-8888}"           # ports de Warpgate (écoute et publication identiques, sur 127.0.0.1 en démo)
SP="${DEMO_SSH_PORT:-2222}"
NETPUB="$NET-pub"
SSHD="it-sshd"
WG="it-warpgate"
WGVOL="it-wg-data-$RUN"
SSHD_IMAGE="adapter-it-sshd:$RUN"

cleanup() {
  jobs -p | xargs -r kill 2>/dev/null || true # le `sleep` de la démo
  docker rm -f "$AD-$RUN" "$CA-$RUN" "$SSHD-$RUN" "$WG-$RUN" >/dev/null 2>&1 || true
  docker network rm "$NET" "$NETPUB" >/dev/null 2>&1 || true
  docker volume rm "$WGVOL" >/dev/null 2>&1 || true
  docker rmi "$SSHD_IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

gorun() { # exécute la commande dans le conteneur Go, code monté en lecture seule
  docker run --rm --user "$UID_GID" -e HOME=/tmp -e GOPATH=/cache/go -e GOCACHE=/cache/build -e GOFLAGS=-mod=readonly -e GOPROXY=off \
    -v "$CACHE":/cache -v "$ROOT":/src:ro -v "$WORK":/work "$@"
}

echo "== génération des secrets jetables"
gorun -w /src "$GO_IMAGE" go run ./integration/gen /work

echo "== réseau interne et step-ca"
docker network create --internal "$NET" >/dev/null
docker run -d --name "$CA-$RUN" --network "$NET" --network-alias "$CA" \
  -e DOCKER_STEPCA_INIT_NAME="Adapter IT CA" -e DOCKER_STEPCA_INIT_DNS_NAMES="$CA,localhost" \
  -e DOCKER_STEPCA_INIT_ADDRESS=":9000" -e DOCKER_STEPCA_INIT_PROVISIONER_NAME="bootstrap" \
  -e DOCKER_STEPCA_INIT_PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -d '/+=')" -e DOCKER_STEPCA_INIT_SSH=true \
  "$STEPCA_IMAGE" >/dev/null

wait_ca() {
  for _ in $(seq 1 60); do
    if docker exec "$CA-$RUN" step ca health --ca-url https://localhost:9000 --root /home/step/certs/root_ca.crt >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  docker logs "$CA-$RUN" | tail -20; echo "step-ca ne démarre pas" >&2; exit 1
}
wait_ca

echo "== ajout du provisioner warpgate-ops et de son modèle SSH"
docker exec -i "$CA-$RUN" sh -c 'mkdir -p /home/step/templates/ssh && cat > /home/step/templates/ssh/warpgate-ops.tpl' < "$WORK/warpgate-ops.tpl"
docker exec "$CA-$RUN" cat /home/step/config/ca.json | python3 -c '
import json, sys
ca = json.load(sys.stdin)
prov = json.load(open(sys.argv[1]))
ca["authority"]["provisioners"].append(prov)
json.dump(ca, sys.stdout)
' "$WORK/provisioner.json" > "$WORK/ca.json.new"
docker exec -i "$CA-$RUN" sh -c 'cat > /home/step/config/ca.json' < "$WORK/ca.json.new"
rm -f "$WORK/ca.json.new" "$WORK/provisioner.json"
docker restart "$CA-$RUN" >/dev/null
wait_ca
docker cp "$CA-$RUN":/home/step/certs/root_ca.crt "$WORK/root_ca.crt"
chmod 0644 "$WORK/root_ca.crt"

echo "== adaptateur (image durcie: lecture seule, sans capacités)"
docker run -d --name "$AD-$RUN" --network "$NET" --network-alias adapter --user "$UID_GID" --read-only \
  --cap-drop ALL --security-opt no-new-privileges --memory 128m -v "$WORK":/etc/adapter:ro \
  "$IMAGE" -config /etc/adapter/config.json >/dev/null
for i in $(seq 1 30); do
  if docker exec "$AD-$RUN" /adapter -healthcheck -config /etc/adapter/config.json >/dev/null 2>&1; then break; fi
  if [ "$i" = 30 ]; then docker logs "$AD-$RUN" | tail -20; echo "l'adaptateur ne démarre pas" >&2; exit 1; fi
  sleep 1
done

if [ "$DEMO" != 1 ]; then
echo "== tests d'intégration"
gorun --network "$NET" -e ADAPTER_URL=https://adapter:8200 -e CA_URL="https://$CA:9000" -e WORK=/work -w /src \
  "$GO_IMAGE" go test -tags integration -count=1 -v ./integration/ || { docker logs "$AD-$RUN" | tail -30; exit 1; }
fi
if [ "${E2E:-0}" = 1 ]; then
  : "${WARPGATE_IMAGE:?}"
  echo "== bout en bout: cible sshd + Warpgate $WARPGATE_IMAGE"
  docker build -q -t "$SSHD_IMAGE" "$ROOT/integration/sshd" >/dev/null
  docker cp "$CA-$RUN":/home/step/certs/ssh_user_ca_key.pub "$WORK/ca.pub"
  chmod 0644 "$WORK/ca.pub"
  # Cible: n'accepte que les certificats de la CA de test. Capacités minimales pour la séparation de privilèges de sshd.
  docker run -d --name "$SSHD-$RUN" --network "$NET" --network-alias sshd-target --security-opt no-new-privileges \
    --cap-drop ALL --cap-add SYS_CHROOT --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add KILL \
    -v "$WORK/ca.pub":/etc/ssh/ca.pub:ro "$SSHD_IMAGE" >/dev/null

  WG_PASS="$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
  WG_TOKEN="$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
  docker volume create "$WGVOL" >/dev/null
  docker run --rm -e WARPGATE_ADMIN_PASSWORD="$WG_PASS" -v "$WGVOL":/data "$WARPGATE_IMAGE" unattended-setup \
    --data-path /data --http-port "$HP" --ssh-port "$SP" --record-sessions --external-host "$([ "$DEMO" = 1 ] && echo localhost || echo warpgate)" \
    --host-key-verification auto-accept --listen-address 0.0.0.0 --if-config-exists skip >/dev/null
  # Warpgate détermine son adresse de pair par une résolution de route vers 1.1.1.1 (échec sur un réseau interne sans route):
  # WARPGATE_PEER_ADDRESS l'évite. Limite constatée (Warpgate 0.30.0): son client Vault n'utilise que des racines publiques intégrées (rustls, ca_certs vide, ni SSL_CERT_FILE ni
  # magasin système) et n'offre aucune option de CA privée: vers l'adaptateur il faut tls_skip_verify (WG_BACKEND_SKIP_VERIFY=1, défaut ici).
  if [ "$DEMO" = 1 ]; then # démo: Warpgate seul sort sur un réseau publié, uniquement sur 127.0.0.1 de l'hôte
    docker network create "$NETPUB" >/dev/null
    WG_NET=(--network "$NETPUB" -p "127.0.0.1:$HP:$HP" -p "127.0.0.1:$SP:$SP")
  else
    WG_NET=(--network "$NET" --network-alias warpgate)
  fi
  docker run -d --name "$WG-$RUN" "${WG_NET[@]}" --security-opt no-new-privileges --cap-drop ALL \
    --read-only --tmpfs /tmp -e WARPGATE_ADMIN_TOKEN="$WG_TOKEN" \
    -e WARPGATE_PEER_ADDRESS="warpgate:$HP" \
    -v "$WGVOL":/data "$WARPGATE_IMAGE" run --enable-admin-token >/dev/null
  if [ "$DEMO" = 1 ]; then docker network connect --alias warpgate "$NET" "$WG-$RUN"; fi
  for i in $(seq 1 60); do
    if docker exec "$WG-$RUN" /usr/local/bin/warpgate healthcheck >/dev/null 2>&1; then break; fi
    if [ "$i" = 60 ]; then docker logs "$WG-$RUN" | tail -20; echo "Warpgate ne démarre pas" >&2; exit 1; fi
    sleep 1
  done

  e2e() { # $1 = phase, le reste = arguments de go test
    local phase="$1"; shift
    gorun --network "$NET" -e WG_API="https://warpgate:$HP" -e WG_SSH="warpgate:$SP" -e WG_TOKEN="$WG_TOKEN" \
      -e WG_ADMIN_PASSWORD="$WG_PASS" -e ADAPTER_TOKEN="$(cat "$WORK/token")" -e ADAPTER_URL=https://adapter:8200 \
      -e WG_BACKEND_SKIP_VERIFY="${WG_BACKEND_SKIP_VERIFY:-1}" -e E2E_PHASE="$phase" -w /src \
      "$GO_IMAGE" go test -tags e2e -count=1 -v "$@" ./integration/e2e/
  }
  if [ "$DEMO" = 1 ]; then
    e2e normal -run 'TestProvisionAndBackendHealth' >/dev/null || { for c in "$WG-$RUN" "$AD-$RUN"; do docker logs "$c" 2>&1 | tail -15; done; echo "configuration de Warpgate impossible" >&2; exit 1; }
    if [ "${DEMO_TEST:-0}" != 1 ]; then cat <<EOF

================================================================================
 DÉMO PRÊTE (tout est local, rien ne sort de votre machine, Ctrl+C pour tout supprimer)

 Navigateur : https://localhost:$HP/@warpgate   (certificat auto-signé : accepter l'avertissement)
   identifiant : admin        mot de passe : $WG_PASS
   Interface utilisateur : liste des cibles, terminal SSH dans le navigateur sur sshd-target.
   Administration : https://localhost:$HP/@warpgate/admin  (Sessions et enregistrements, Config > Secret backends).

 SSH depuis ce terminal :
   ssh -p $SP -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin:sshd-target@localhost
   (mot de passe ci-dessus ; une fois connecté : id, hostname ; le compte est "ops")

 Cibles pièges (doivent échouer) : sshd-badprincipal, sshd-forbiddenrole, sshd-blockedpath
   ssh -p $SP ... admin:sshd-badprincipal@localhost

 Preuves dans un autre terminal :
   docker logs $SSHD-$RUN 2>&1 | grep Accepted     # certificat accepté par sshd, avec l'identité warpgate:admin:<session>
   docker logs $AD-$RUN 2>&1 | grep '"event":"sign"'  # journal d'audit de l'adaptateur
================================================================================
EOF
    fi
    if [ "${DEMO_TEST:-0}" = 1 ]; then
      echo "== test de la démo : navigateur simulé (curl) et vrai client ssh"
      ASK="$WORK/askpass.sh"; printf '#!/bin/sh\necho "%s"\n' "$WG_PASS" > "$ASK"; chmod 700 "$ASK"
      fail() { echo "ÉCHEC démo: $*" >&2; for c in "$WG-$RUN" "$SSHD-$RUN" "$AD-$RUN"; do echo "--- $c" >&2; docker logs "$c" 2>&1 | tail -15 >&2; done; exit 1; }
      sshw() { # $1 = cible, le reste = commande distante ; mot de passe fourni par SSH_ASKPASS (OpenSSH 8.4 ou plus)
        local t="$1"; shift
        SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 timeout 40 ssh -p "$SP" -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=15 \
          -o PreferredAuthentications=password,keyboard-interactive "admin:$t@localhost" "$@" </dev/null
      }
      [ "$(curl -sk -m 15 -o /dev/null -w '%{http_code}' "https://localhost:$HP/@warpgate")" = 200 ] || fail "interface web injoignable"
      out="$(sshw sshd-target id -un 2>&1)" || fail "ssh vers sshd-target a échoué: $out"
      [ "$out" = ops ] || fail "sshd-target: compte \"$out\", attendu ops"
      for t in sshd-badprincipal sshd-forbiddenrole sshd-blockedpath; do
        out="$(sshw "$t" id -un 2>&1)" || true
        [ "$out" != ops ] || fail "$t: la cible piégée a atteint le compte ops"
      done
      SSHLOG="$(docker logs "$SSHD-$RUN" 2>&1)"
      printf '%s\n' "$SSHLOG" | grep -qE 'Accepted publickey for ops from [^ ]+ port [0-9]+ ssh2: ED25519-CERT SHA256:[^ ]+ ID warpgate:admin:[^ ]+ \(serial [0-9]+\) CA ' || fail "aucun certificat accepté dans le journal de sshd"
      if printf '%s\n' "$SSHLOG" | grep -qE 'Accepted .* for (postgres|root)'; then fail "connexion acceptée pour un compte interdit"; fi
      docker logs "$AD-$RUN" 2>&1 | grep -q '"event":"sign","result":"ok"' || fail "aucune signature dans le journal de l'adaptateur"
      echo "DEMO OK"
      exit 0
    fi
    sleep 2147483647 & wait $! # `wait` laisse Ctrl+C déclencher le nettoyage tout de suite
  fi
  e2e normal || { for c in "$WG-$RUN" "$SSHD-$RUN" "$AD-$RUN"; do echo "--- $c"; docker logs "$c" 2>&1 | tail -25; done; exit 1; }

  echo "== preuves côté cible et adaptateur"
  SSHLOG="$(docker logs "$SSHD-$RUN" 2>&1)"
  ADLOG="$(docker logs "$AD-$RUN" 2>&1)"
  accepted="$(printf '%s\n' "$SSHLOG" | grep -cE 'Accepted publickey for ops from [^ ]+ port [0-9]+ ssh2: ED25519-CERT SHA256:[^ ]+ ID warpgate:admin:[^ ]+ \(serial [0-9]+\) CA ' || true)"
  echo "connexions sshd par certificat signé par la CA de test: $accepted (attendu: 2 ou plus)"
  [ "$accepted" -ge 2 ] || { printf '%s\n' "$SSHLOG" | tail -20; echo "ÉCHEC: pas de connexion par certificat dans le journal de sshd" >&2; exit 1; }
  if printf '%s\n' "$SSHLOG" | grep -qE 'Accepted .* for (postgres|root)'; then echo "ÉCHEC: connexion acceptée pour un compte interdit" >&2; exit 1; fi
  printf '%s\n' "$ADLOG" | grep -q '"reason":"principal_interdit"' || { echo "ÉCHEC: refus du principal absent du journal de l'adaptateur" >&2; exit 1; }
  printf '%s\n' "$ADLOG" | grep -q '"reason":"jeton_ou_role_refuse"' || { echo "ÉCHEC: refus du rôle absent du journal de l'adaptateur" >&2; exit 1; }
  if printf '%s\n' "$ADLOG" | grep -q "$(cat "$WORK/token")"; then echo "ÉCHEC: le jeton apparaît dans le journal de l'adaptateur" >&2; exit 1; fi

  echo "== adaptateur arrêté: Warpgate doit échouer fermé"
  docker stop "$AD-$RUN" >/dev/null
  e2e down -run TestFailsClosedWhenAdapterIsDown
  if [ "$(docker logs "$SSHD-$RUN" 2>&1 | grep -cE 'Accepted publickey for ops')" -ne "$accepted" ]; then
    echo "ÉCHEC: une connexion de plus a été acceptée alors que l'adaptateur était arrêté" >&2; exit 1
  fi
  echo "E2E OK"
fi

echo "== journal d'audit de l'adaptateur (extrait)"
docker logs "$AD-$RUN" 2>&1 | grep '"event":"sign"' | tail -5 || true
