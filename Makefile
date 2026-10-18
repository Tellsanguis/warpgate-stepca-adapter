SHELL := /bin/bash
.DEFAULT_GOAL := help

# Images épinglées par digest (mises à jour par Renovate, jamais "latest").
GO_IMAGE       := golang@sha256:957861185dbf29d93668ace41e011d091c6e779953d47f0316ef2cc58e28fe2b
STEPCA_IMAGE   := smallstep/step-ca@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270
WARPGATE_IMAGE := ghcr.io/warp-tech/warpgate@sha256:8d0899c48c7dae1833d0ff1af4f47417bd7324fa7dad15aa4a727cb83d598ec6 # 0.30.0
HADOLINT_IMAGE := hadolint/hadolint@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d
TRIVY_IMAGE    := aquasec/trivy@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222
IMAGE          := warpgate-stepca-adapter:dev

# Outils Go épinglés par version.
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOSEC       := github.com/securego/gosec/v2/cmd/gosec@v2.29.0

# Le code est monté en lecture seule, les caches sont dans un volume Docker.
UID := $(shell id -u)
GID := $(shell id -g)
CACHE := warpgate-adapter-gocache
# `make GORUN= vet test ...` exécute les mêmes commandes directement (utilisé par l'intégration continue, déjà dans un conteneur Go).
GORUN = docker run --rm --user $(UID):$(GID) -e HOME=/tmp -e GOPATH=/cache/go -e GOCACHE=/cache/build \
        -e GOFLAGS=-mod=readonly -e CGO_ENABLED=1 -v $(CACHE):/cache -v "$(CURDIR)":/src:ro -w /src $(GO_IMAGE)

.PHONY: demo e2e help init-cache tidy fmt vet test cover fuzz vuln lint sec build image hadolint scan integration security strix

help: ## Liste des commandes
	@grep -E '^[a-z0-9-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

init-cache: ## Crée le volume de cache Go et y télécharge les modules (une fois, seul moment avec le réseau)
	docker volume create $(CACHE) >/dev/null
	docker run --rm --user 0 -v $(CACHE):/cache $(GO_IMAGE) chown -R $(UID):$(GID) /cache
	@# Les étapes suivantes (integration, e2e) tournent hors ligne (GOPROXY=off) : sans ce remplissage, un cache neuf (CI) échoue.
	docker run --rm --user $(UID):$(GID) -e HOME=/tmp -e GOPATH=/cache/go -e GOCACHE=/cache/build \
	  -v $(CACHE):/cache -v "$(CURDIR)":/src -w /src $(GO_IMAGE) go mod download

tidy: ## go mod tidy (seule commande qui écrit dans le dépôt)
	docker run --rm --user $(UID):$(GID) -e HOME=/tmp -e GOPATH=/cache/go -e GOCACHE=/cache/build \
	  -v $(CACHE):/cache -v "$(CURDIR)":/src -w /src $(GO_IMAGE) go mod tidy

fmt: ## Échoue si le code n'est pas formaté
	@out=$$($(GORUN) gofmt -l .); if [ -n "$$out" ]; then echo "non formaté :"; echo "$$out"; exit 1; fi

vet: ## go vet
	$(GORUN) go vet ./...

test: ## Tests unitaires avec détecteur de courses
	$(GORUN) go test -race -count=1 ./...

cover: ## Couverture
	$(GORUN) go test -count=1 -cover ./...

fuzz: ## Fuzzing court (30 s par cible)
	$(GORUN) sh -c 'for t in $$(grep -h "^func Fuzz" *_test.go | sed "s/func \(Fuzz[A-Za-z0-9_]*\).*/\1/"); do go test -run=^$$ -fuzz=^$$t$$ -fuzztime=30s . || exit 1; done'

vuln: ## Dépendances et bibliothèque standard vulnérables
	$(GORUN) sh -c 'go install $(GOVULNCHECK) && $$(go env GOPATH)/bin/govulncheck ./...'

lint: ## staticcheck
	$(GORUN) sh -c 'go install $(STATICCHECK) && $$(go env GOPATH)/bin/staticcheck ./...'

sec: ## gosec (analyse statique de sécurité)
	$(GORUN) sh -c 'go install $(GOSEC) && $$(go env GOPATH)/bin/gosec -quiet ./...'

build: ## Binaire statique dans l'image
	docker build -t $(IMAGE) .

image: build

hadolint: ## Lint du Dockerfile
	docker run --rm -i $(HADOLINT_IMAGE) < Dockerfile

scan: build ## Vulnérabilités de l'image (trivy, sans donner le socket Docker au conteneur)
	docker save $(IMAGE) -o /tmp/warpgate-adapter-image.tar
	docker run --rm -v /tmp/warpgate-adapter-image.tar:/image.tar:ro $(TRIVY_IMAGE) image --quiet --no-progress --input /image.tar --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed
	rm -f /tmp/warpgate-adapter-image.tar

integration: ## Tests contre un vrai step-ca éphémère (voir integration/README.md)
	STEPCA_IMAGE=$(STEPCA_IMAGE) GO_IMAGE=$(GO_IMAGE) UID_GID=$(UID):$(GID) CACHE=$(CACHE) ./integration/run.sh

e2e: build ## Bout en bout: Warpgate 0.30.0 réel + adaptateur + step-ca + sshd cible (Docker local)
	E2E=1 WARPGATE_IMAGE=$(WARPGATE_IMAGE) STEPCA_IMAGE=$(STEPCA_IMAGE) GO_IMAGE=$(GO_IMAGE) UID_GID=$(UID):$(GID) CACHE=$(CACHE) ./integration/run.sh

demo: build ## Démo locale à essayer à la main: https://localhost:8888 et ssh -p 2222 (Ctrl+C supprime tout)
	E2E=1 DEMO=1 WARPGATE_IMAGE=$(WARPGATE_IMAGE) STEPCA_IMAGE=$(STEPCA_IMAGE) GO_IMAGE=$(GO_IMAGE) UID_GID=$(UID):$(GID) CACHE=$(CACHE) ./integration/run.sh

security: fmt vet test fuzz vuln lint sec hadolint scan ## Toute la chaîne de sécurité (hors Strix)

strix: ## Passe Strix (clé de modèle requise)
	./scripts/strix.sh
