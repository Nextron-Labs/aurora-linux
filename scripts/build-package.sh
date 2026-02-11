#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${GOARCH:?GOARCH is required}"
: "${BINARY_PATH:?BINARY_PATH is required}"
: "${SIGMA_REPO_DIR:?SIGMA_REPO_DIR is required}"

DIST_DIR="${DIST_DIR:-dist}"
PACKAGE_NAME="aurora-linux-${VERSION}-linux-${GOARCH}"

if [[ ! -f "${BINARY_PATH}" ]]; then
	echo "binary not found at ${BINARY_PATH}" >&2
	exit 1
fi

if [[ ! -d "${SIGMA_REPO_DIR}/rules/linux" ]]; then
	echo "Sigma rules directory not found at ${SIGMA_REPO_DIR}/rules/linux" >&2
	exit 1
fi

mkdir -p "${DIST_DIR}"

stage_dir="$(mktemp -d)"
trap 'rm -rf "${stage_dir}"' EXIT

package_root="${stage_dir}/${PACKAGE_NAME}"
install_root="${package_root}/opt/aurora-linux"

mkdir -p \
	"${install_root}/config" \
	"${install_root}/deploy" \
	"${install_root}/sigma-rules/rules"

install -m 0755 "${BINARY_PATH}" "${install_root}/aurora-linux"
install -m 0644 deploy/aurora-linux.service "${install_root}/deploy/aurora-linux.service"
install -m 0644 deploy/aurora-linux.env "${install_root}/config/aurora-linux.env"
cp -a "${SIGMA_REPO_DIR}/rules/linux" "${install_root}/sigma-rules/rules/"

sigma_sha="unknown"
if git -C "${SIGMA_REPO_DIR}" rev-parse HEAD >/dev/null 2>&1; then
	sigma_sha="$(git -C "${SIGMA_REPO_DIR}" rev-parse HEAD)"
fi

cat >"${install_root}/sigma-rules/SOURCE.txt" <<EOF
repo=https://github.com/SigmaHQ/sigma
commit=${sigma_sha}
included_path=rules/linux
EOF

tar -C "${stage_dir}" -czf "${DIST_DIR}/${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}"
echo "wrote ${DIST_DIR}/${PACKAGE_NAME}.tar.gz"
