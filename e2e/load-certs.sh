#!/usr/bin/env bash
set -euo pipefail
# Single-cluster variant: Keycloak + Breakglass controller + webhook auth all in one kind cluster.
# Replaces previous hub+tenant topology by creating only one cluster and using a ClusterConfig
# that points back to the same cluster (simulated tenant "tenant-a").

# --- Tools (can be overridden by env) ---
KUBECTL=${KUBECTL:-kubectl}
KUSTOMIZE=${KUSTOMIZE:-bin/kustomize}

# --- TLS / temp directories (kept as before, but configurable) ---
TDIR=${TDIR:-}
TLS_DIR=${TLS_DIR:-}

# --- Keycloak ---
KEYCLOAK_HOST=${KEYCLOAK_HOST:-breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local}
CONTROLLER_FORWARD_PORT=${CONTROLLER_FORWARD_PORT:-28081} # local port forwarded to controller svc:8080


REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TDIR=${TDIR:-"$REPO_ROOT/e2e/kind-setup-single-tdir"}
mkdir -p "$TDIR"
KEYCLOAK_CA_FILE="$TDIR/keycloak-ca.crt"

TLS_DIR=${TLS_DIR:-"$REPO_ROOT/e2e/kind-setup-single-tls"}
mkdir -p "$TLS_DIR"
OPENSSL_CONF_KEYCLOAK="$TLS_DIR/req.cnf"

# Default HUB_KUBECONFIG to repo-local files (can be overridden)
HUB_KUBECONFIG=${HUB_KUBECONFIG:-"$REPO_ROOT/e2e/kind-setup-single-hub-kubeconfig.yaml"}

# Pre-generate CA/certs for Keycloak so we can embed CA into auth config before cluster creation
cat > "$OPENSSL_CONF_KEYCLOAK" << EOF
[ req ]
distinguished_name = dn
req_extensions = req_ext
prompt = no
[ dn ]
CN = keycloak.keycloak.svc.cluster.local
[ req_ext ]
subjectAltName = @alt_names
[ alt_names ]
DNS.1 = keycloak
DNS.2 = keycloak.keycloak
DNS.3 = keycloak.keycloak.svc
DNS.4 = keycloak.keycloak.svc.cluster.local
DNS.5 = localhost
DNS.6 = ${KEYCLOAK_HOST}
DNS.7 = breakglass-dev-keycloak
DNS.8 = breakglass.system.svc.cluster.local
EOF
openssl genrsa -out "$TLS_DIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$TLS_DIR/ca.key" -subj "/CN=breakglass-keycloak-ca" -days 365 -out "$TLS_DIR/ca.crt"
openssl genrsa -out "$TLS_DIR/server.key" 2048
openssl req -new -key "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" -config "$OPENSSL_CONF_KEYCLOAK"
openssl x509 -req -in "$TLS_DIR/server.csr" -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial -out "$TLS_DIR/server.crt" -days 365 -extensions req_ext -extfile "$OPENSSL_CONF_KEYCLOAK"
cp "$TLS_DIR/ca.crt" "$KEYCLOAK_CA_FILE"

# Use the dev namespace kustomize writes to (namePrefix on config/dev is breakglass-dev- and namespace is breakglass-dev-system)
DEV_NS=breakglass-dev-system
$KUBECTL create namespace "$DEV_NS" --dry-run=client -o yaml | $KUBECTL apply -f - || true
$KUBECTL create secret tls keycloak-tls -n "$DEV_NS" --cert="$TLS_DIR/server.crt" --key="$TLS_DIR/server.key" --dry-run=client -o yaml | $KUBECTL apply -f -
# Create breakglass-dev-certs ConfigMap from generated CA so deployments mounting it succeed
$KUBECTL create configmap breakglass-dev-certs -n "$DEV_NS" --from-file=ca.crt="$TLS_DIR/ca.crt" --dry-run=client -o yaml | $KUBECTL apply -f -


# Patch the generated config ConfigMap in-cluster to embed the generated CA so the
# running controller can validate Keycloak TLS. The configMap created by the kustomize
# overlay is namePrefix'd to 'breakglass-dev-config' in namespace $DEV_NS.
TMP_CFG="$TDIR/tmp-config-with-ca.yaml"
if [ -f "$TLS_DIR/ca.crt" ]; then
  # indent CA so it nests properly under data.config.yaml -> authorizationServer -> certificateAuthority
  CA_INLINE=$(sed 's/^/        /' "$TLS_DIR/ca.crt")
else
  CA_INLINE=""
fi
cat > "$TMP_CFG" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: breakglass-dev-config
  namespace: $DEV_NS
data:
  config.yaml: |
    server:
      listenAddress: 0.0.0.0:8080
    authorizationServer:
      url: https://breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local:8443
      jwksEndpoint: "realms/breakglass-e2e/protocol/openid-connect/certs"
      certificateAuthority: |
$CA_INLINE
    frontend:
      oidcAuthority: https://localhost:8443/realms/breakglass-e2e
      oidcClientID: breakglass-ui
      baseURL: http://localhost:${CONTROLLER_FORWARD_PORT}
    mail:
      host: breakglass-dev-mailhog.breakglass-dev-system.svc.cluster.local
      port: 1025
      insecureSkipVerify: true
    kubernetes:
      context: ""
      oidcPrefixes:
        - "keycloak:"
        - "oidc:"

EOF

# Determine the kustomize-generated ConfigMap name (it has a hash suffix) and apply the patched data to that exact name
# Wait for the kustomize-generated ConfigMap to appear; it has a hash suffix and may not be immediately present
TARGET_NAME=""
for i in {1..60}; do
  CFG_NAME=$($KUBECTL -n "$DEV_NS" get cm -o name 2>/dev/null | sed 's#configmap/##' | grep '^breakglass-dev-config' | head -n1 || true)
  if [ -n "$CFG_NAME" ]; then
    TARGET_NAME="$CFG_NAME"
    break
  fi
  sleep 1
done
if [ -z "$TARGET_NAME" ]; then
  TARGET_NAME=breakglass-dev-config
fi

# Rewrite TMP_CFG with the actual target name so apply updates the live ConfigMap
cat > "$TMP_CFG" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: $TARGET_NAME
  namespace: $DEV_NS
data:
  config.yaml: |
    server:
      listenAddress: 0.0.0.0:8080
    authorizationServer:
      url: https://breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local:8443
      jwksEndpoint: "realms/breakglass-e2e/protocol/openid-connect/certs"
      certificateAuthority: |
$CA_INLINE
    frontend:
      oidcAuthority: https://localhost:8443/realms/breakglass-e2e
      oidcClientID: breakglass-ui
      baseURL: http://localhost:${CONTROLLER_FORWARD_PORT}
    mail:
      host: breakglass-dev-mailhog.breakglass-dev-system.svc.cluster.local
      port: 1025
      insecureSkipVerify: true
    kubernetes:
      context: ""
      oidcPrefixes:
        - "keycloak:"
        - "oidc:"
EOF

$KUBECTL apply -f "$TMP_CFG" || log "Warning: failed to apply patched $TARGET_NAME"

$KUSTOMIZE build config/dev | $KUBECTL apply -f -