#!/usr/bin/env bash
set -euo pipefail

# Install gated for a single developer workstation.
# No root. No sudo. Everything under $HOME.
#
# Usage:
#   ./scripts/install-user.sh                    # install latest
#   ./scripts/install-user.sh 1.2.0              # install specific version
#   ARTIFACTORY_URL=https://... ./scripts/install-user.sh  # from Artifactory

VERSION="${1:-latest}"
INSTALL_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/gated"
STATE_DIR="${HOME}/.local/share/gated/verdicts"
SYSTEMD_DIR="${HOME}/.config/systemd/user"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac

mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}/policy" "${STATE_DIR}" "${SYSTEMD_DIR}"

echo "=== Installing gated ${VERSION} for ${OS}/${ARCH} ==="

# If ARTIFACTORY_URL is set, pull from there. Otherwise, build from source.
if [ -n "${ARTIFACTORY_URL:-}" ]; then
    echo "[fetch] Binary from Artifactory..."
    curl -sf -H "Authorization: Bearer ${ARTIFACTORY_TOKEN}" \
        "${ARTIFACTORY_URL}/internal-tools-generic/gated/${VERSION}/gated-${OS}-${ARCH}" \
        -o "${INSTALL_DIR}/gated"
    chmod 755 "${INSTALL_DIR}/gated"
else
    echo "[build] No ARTIFACTORY_URL set, checking for local binary..."
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

    if [ -f "${PROJECT_DIR}/gated" ]; then
        cp "${PROJECT_DIR}/gated" "${INSTALL_DIR}/gated"
        chmod 755 "${INSTALL_DIR}/gated"
    elif command -v go >/dev/null 2>&1; then
        echo "[build] Building from source..."
        (cd "${PROJECT_DIR}" && go build -trimpath -ldflags="-s -w" -o "${INSTALL_DIR}/gated" ./cmd/gated)
    else
        echo "ERROR: No binary found and Go not installed. Build first with 'make build' or set ARTIFACTORY_URL."
        exit 1
    fi
fi

echo "[ok] gated -> ${INSTALL_DIR}/gated"

# Install scan tools if missing.
install_tool_user() {
    local name="$1" url="$2" binary="$3"

    if command -v "${binary}" >/dev/null 2>&1; then
        echo "[skip] ${name} already installed: $(command -v "${binary}")"
        return
    fi

    echo "[install] ${name}..."
    local tmp
    tmp="$(mktemp -d)"

    curl -sSfL "${url}" -o "${tmp}/archive"

    case "${url}" in
        *.tar.gz)
            tar -xzf "${tmp}/archive" -C "${tmp}"
            install -m755 "${tmp}/${binary}" "${INSTALL_DIR}/${binary}"
            ;;
        *)
            install -m755 "${tmp}/archive" "${INSTALL_DIR}/${binary}"
            ;;
    esac
    rm -rf "${tmp}"
    echo "[ok] ${binary} -> ${INSTALL_DIR}/${binary}"
}

SYFT_VERSION="${SYFT_VERSION:-1.20.0}"
GRYPE_VERSION="${GRYPE_VERSION:-0.87.0}"
OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-1.9.1}"
OPA_VERSION="${OPA_VERSION:-1.4.2}"

install_tool_user "syft" \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_${OS}_${ARCH}.tar.gz" \
    "syft"

install_tool_user "grype" \
    "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_${OS}_${ARCH}.tar.gz" \
    "grype"

install_tool_user "osv-scanner" \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${OSV_SCANNER_VERSION}_${OS}_${ARCH}.tar.gz" \
    "osv-scanner"

install_tool_user "opa" \
    "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_${OS}_${ARCH}_static" \
    "opa"

# Warm grype DB.
echo "[init] Updating grype vulnerability database..."
"${INSTALL_DIR}/grype" db update 2>/dev/null || echo "[warn] grype db update failed — will retry on first scan"

# Install config and policies if not already present.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
    if [ -f "${PROJECT_DIR}/configs/config.user.yaml" ]; then
        cp "${PROJECT_DIR}/configs/config.user.yaml" "${CONFIG_DIR}/config.yaml"
    fi
    echo "[ok] Config -> ${CONFIG_DIR}/config.yaml"
fi

# Copy policies.
for f in "${PROJECT_DIR}"/policy/*.rego "${PROJECT_DIR}"/policy/data.json; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    if [ ! -f "${CONFIG_DIR}/policy/${base}" ]; then
        cp "$f" "${CONFIG_DIR}/policy/${base}"
        echo "[ok] Policy -> ${CONFIG_DIR}/policy/${base}"
    fi
done

# Install user systemd unit.
if [ -f "${PROJECT_DIR}/init/systemd/gated-user.service" ]; then
    cp "${PROJECT_DIR}/init/systemd/gated-user.service" "${SYSTEMD_DIR}/gated.service"
    echo "[ok] Systemd unit -> ${SYSTEMD_DIR}/gated.service"
fi

# Validate.
echo ""
echo "=== Validating ==="
"${INSTALL_DIR}/gated" -config "${CONFIG_DIR}/config.yaml" -validate && echo "[ok] Config and policies valid."

echo ""
echo "=== Done ==="
echo ""
echo "To start manually:  gated -config ~/.config/gated/config.yaml"
echo "To start as service: systemctl --user enable --now gated"
echo "To view logs:        journalctl --user -u gated -f"
echo "To reload policies:  systemctl --user reload gated"
echo ""
echo "Make sure ${INSTALL_DIR} is in your PATH."
