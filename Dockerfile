# Images épinglées par digest (Renovate propose les montées).
FROM golang@sha256:957861185dbf29d93668ace41e011d091c6e779953d47f0316ef2cc58e28fe2b AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /adapter .

# Sans shell, sans gestionnaire de paquets, utilisateur non root.
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /adapter /adapter
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/adapter", "-healthcheck"]
ENTRYPOINT ["/adapter"]
