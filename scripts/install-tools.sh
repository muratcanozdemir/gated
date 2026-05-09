#!/usr/bin/env bash
set -euo pipefail

# Install scan toolchain for gate-daemon.
# All tools are Apache-2.0 or equivalent permissive licenses.
# Override versions via environment variables.

SYFT_VERSION="${SYFT_VERSION:-1.20.0}"
GRYPE_VERSION="${GRYPE_VERSION:-0.87.0}"
OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-1.9.1}"
OPA_VERSION="${OPA_VERSION:-1.4.2}"

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)       echo "Unsupported architecture: ${ARCH}" >&2; exit 1 ;;
esac

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"

install_tool() {
    local name="$1" url="$2" binary="$3"

    if command -v "${binary}" >/dev/null 2>&1; then
        echo "[skip] ${name} already installed: $(command -v "${binary}")"
        return
    fi

    echo "[install] ${name}..."
    local tmp
    tmp="$(mktemp -d)"
    trap "rm -rf '${tmp}'" RETURN

    curl -sSfL "${url}" -o "${tmp}/archive"

    case "${url}" in
        *.tar.gz)
            tar -xzf "${tmp}/archive" -C "${tmp}"
            install -m755 "${tmp}/${binary}" "${INSTALL_DIR}/${binary}"
            ;;
        *.zip)
            unzip -q "${tmp}/archive" -d "${tmp}"
            install -m755 "${tmp}/${binary}" "${INSTALL_DIR}/${binary}"
            ;;
        *)
            # Direct binary download (OPA style).
            install -m755 "${tmp}/archive" "${INSTALL_DIR}/${binary}"
            ;;
    esac

    echo "[ok] ${name} ${binary} -> ${INSTALL_DIR}/${binary}"
}

# Syft — SBOM generator.
install_tool "syft ${SYFT_VERSION}" \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_${OS}_${ARCH}.tar.gz" \
    "syft"

# Grype — vulnerability scanner.
install_tool "grype ${GRYPE_VERSION}" \
    "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_${OS}_${ARCH}.tar.gz" \
    "grype"

# OSV-Scanner — Google's vulnerability database scanner.
install_tool "osv-scanner ${OSV_SCANNER_VERSION}" \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${OSV_SCANNER_VERSION}_${OS}_${ARCH}.tar.gz" \
    "osv-scanner"

# OPA — Open Policy Agent.
install_tool "opa ${OPA_VERSION}" \
    "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_${OS}_${ARCH}_static" \
    "opa"

# Warm grype vulnerability database.
echo "[init] Updating grype vulnerability database..."
grype db update || echo "[warn] grype db update failed — will retry on first scan"

echo "[done] All tools installed to ${INSTALL_DIR}"
