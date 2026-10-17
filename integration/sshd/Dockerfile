# Cible SSH de test: n'accepte QUE les certificats signés par la CA de test (clé montée en /etc/ssh/ca.pub), compte `ops` seulement.
FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
# hadolint ignore=DL3018
RUN apk add --no-cache openssh-server \
 && adduser -D -s /bin/sh ops \
 && sed -i 's/^ops:!:/ops:*:/' /etc/shadow \
 && mkdir -p /etc/ssh/auth_principals \
 && printf 'ops\n' > /etc/ssh/auth_principals/ops \
 && ssh-keygen -A
COPY sshd_config /etc/ssh/sshd_config
EXPOSE 22
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
