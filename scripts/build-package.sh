#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${GOARCH:?GOARCH is required}"
: "${BINARY_PATH:?BINARY_PATH is required}"
: "${SIGMA_REPO_DIR:?SIGMA_REPO_DIR is required}"
UTILITY_BINARY_PATH="${UTILITY_BINARY_PATH:-}"

DIST_DIR="${DIST_DIR:-dist}"
normalized_version="${VERSION#v}"
PACKAGE_NAME="aurora-linux-v${normalized_version}-linux-${GOARCH}"
ARCHIVE_NAME="${PACKAGE_NAME}.tar.gz"

if [[ ! -f "${BINARY_PATH}" ]]; then
	echo "binary not found at ${BINARY_PATH}" >&2
	exit 1
fi

if [[ -n "${UTILITY_BINARY_PATH}" && ! -f "${UTILITY_BINARY_PATH}" ]]; then
	echo "utility binary not found at ${UTILITY_BINARY_PATH}" >&2
	exit 1
fi

if [[ ! -d "${SIGMA_REPO_DIR}/rules/linux" ]]; then
	echo "Sigma rules directory not found at ${SIGMA_REPO_DIR}/rules/linux" >&2
	exit 1
fi

mkdir -p "${DIST_DIR}"

package_root="${DIST_DIR}/${PACKAGE_NAME}"
rm -rf "${package_root}"
mkdir -p \
	"${package_root}/config" \
	"${package_root}/deploy" \
	"${package_root}/deploy/templates" \
	"${package_root}/scripts" \
	"${package_root}/sigma-rules"

install -m 0755 "${BINARY_PATH}" "${package_root}/aurora"
if [[ -n "${UTILITY_BINARY_PATH}" ]]; then
	install -m 0755 "${UTILITY_BINARY_PATH}" "${package_root}/aurora-util"
fi
install -m 0644 deploy/aurora.service "${package_root}/deploy/aurora.service"
install -m 0644 deploy/aurora.env "${package_root}/config/aurora.env"
install -m 0644 deploy/templates/aurora.env.example "${package_root}/config/aurora.env.example"
install -m 0644 deploy/templates/rsyslog-aurora.conf.example "${package_root}/deploy/templates/rsyslog-aurora.conf.example"
install -m 0644 deploy/templates/aurora-maintenance.cron.example "${package_root}/deploy/templates/aurora-maintenance.cron.example"
install -m 0755 scripts/install-service.sh "${package_root}/scripts/install-service.sh"
install -m 0755 scripts/install-maintenance-cron.sh "${package_root}/scripts/install-maintenance-cron.sh"
cp -a "${SIGMA_REPO_DIR}/rules/linux" "${package_root}/sigma-rules/"
chmod 0755 "${package_root}/aurora"
if [[ -f "${package_root}/aurora-util" ]]; then
	chmod 0755 "${package_root}/aurora-util"
fi

sigma_sha="unknown"
if git -C "${SIGMA_REPO_DIR}" rev-parse HEAD >/dev/null 2>&1; then
	sigma_sha="$(git -C "${SIGMA_REPO_DIR}" rev-parse HEAD)"
fi

cat >"${package_root}/sigma-rules/SOURCE.txt" <<EOF
repo=https://github.com/SigmaHQ/sigma
commit=${sigma_sha}
included_path=rules/linux
EOF

if [[ -f "LICENSE" ]]; then
	install -m 0644 LICENSE "${package_root}/LICENSE"
fi

cat >"${package_root}/README.md" <<'EOF'
# Aurora Linux Bundle

Run as root:

```bash
sudo ./aurora --rules ./sigma-rules/linux/ --json
```

Output is NDJSON (one JSON object per line). Example:

```bash
sudo ./aurora --rules ./sigma-rules/linux/ --json | jq -c .
```
EOF

(
	cd "${package_root}"
	if command -v sha256sum >/dev/null 2>&1; then
		find . -type f ! -name checksums.txt -print0 | sort -z | xargs -0 sha256sum > checksums.txt
	else
		find . -type f ! -name checksums.txt -print0 | sort -z | xargs -0 shasum -a 256 > checksums.txt
	fi
)

(
	cd "${DIST_DIR}"
	tar -czf "${ARCHIVE_NAME}" "${PACKAGE_NAME}"
)

archive_path="${DIST_DIR}/${ARCHIVE_NAME}"
mapfile -t archive_roots < <(tar -tzf "${archive_path}" | awk -F/ 'NF > 0 {print $1}' | sort -u)
if [[ "${#archive_roots[@]}" -ne 1 || "${archive_roots[0]}" != "${PACKAGE_NAME}" ]]; then
	echo "archive root validation failed: expected only ${PACKAGE_NAME}, got: ${archive_roots[*]}" >&2
	exit 1
fi

echo "wrote ${archive_path}"
echo "archive preview:"
tar -tzf "${archive_path}" | sed -n '1,10p'
