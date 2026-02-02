#!/usr/bin/env bash
set -Eeuo pipefail

# LICENSE: https://github.com/hakadoriya/log.sh/blob/HEAD/LICENSE
# Common
if [ "${LOGSH_COLOR:-}" ] || [ -t 2 ] ; then LOGSH_COLOR=true; else LOGSH_COLOR=''; fi
_logshRFC3339() { date "+%Y-%m-%dT%H:%M:%S%z" | sed "s/\(..\)$/:\1/"; }
_logshCmd() { for a in "$@"; do if echo "${a:-}" | grep -Eq "[[:blank:]]"; then printf "'%s' " "${a:-}"; else printf "%s " "${a:-}"; fi; done | sed "s/ $//"; }
# Color
LogshDefault() { test "  ${LOGSH_LEVEL:-0}" -gt 000 || echo "$*" | awk "{print   \"$(_logshRFC3339) [${LOGSH_COLOR:+\\033[0;35m}  DEFAULT${LOGSH_COLOR:+\\033[0m}] \"\$0\"\"}" 1>&2; }
LogshDebug() { test "    ${LOGSH_LEVEL:-0}" -gt 100 || echo "$*" | awk "{print   \"$(_logshRFC3339) [${LOGSH_COLOR:+\\033[0;34m}    DEBUG${LOGSH_COLOR:+\\033[0m}] \"\$0\"\"}" 1>&2; }
LogshInfo() { test "     ${LOGSH_LEVEL:-0}" -gt 200 || echo "$*" | awk "{print   \"$(_logshRFC3339) [${LOGSH_COLOR:+\\033[0;32m}     INFO${LOGSH_COLOR:+\\033[0m}] \"\$0\"\"}" 1>&2; }
LogshNotice() { test "   ${LOGSH_LEVEL:-0}" -gt 300 || echo "$*" | awk "{print   \"$(_logshRFC3339) [${LOGSH_COLOR:+\\033[0;36m}   NOTICE${LOGSH_COLOR:+\\033[0m}] \"\$0\"\"}" 1>&2; }
LogshWarn() { test "     ${LOGSH_LEVEL:-0}" -gt 400 || echo "$*" | awk "{print   \"$(_logshRFC3339) [${LOGSH_COLOR:+\\033[0;33m}     WARN${LOGSH_COLOR:+\\033[0m}] \"\$0\"\"}" 1>&2; }
LogshWarning() { test "  ${LOGSH_LEVEL:-0}" -gt 400 || echo "$*" | awk "{print   \"$(_logshRFC3339) [${LOGSH_COLOR:+\\033[0;33m}  WARNING${LOGSH_COLOR:+\\033[0m}] \"\$0\"\"}" 1>&2; }
LogshError() { test "    ${LOGSH_LEVEL:-0}" -gt 500 || echo "$*" | awk "{print   \"$(_logshRFC3339) [${LOGSH_COLOR:+\\033[0;31m}    ERROR${LOGSH_COLOR:+\\033[0m}] \"\$0\"\"}" 1>&2; }
LogshCritical() { test " ${LOGSH_LEVEL:-0}" -gt 600 || echo "$*" | awk "{print \"$(_logshRFC3339) [${LOGSH_COLOR:+\\033[0;1;31m} CRITICAL${LOGSH_COLOR:+\\033[0m}] \"\$0\"\"}" 1>&2; }
LogshAlert() { test "    ${LOGSH_LEVEL:-0}" -gt 700 || echo "$*" | awk "{print   \"$(_logshRFC3339) [${LOGSH_COLOR:+\\033[0;41m}    ALERT${LOGSH_COLOR:+\\033[0m}] \"\$0\"\"}" 1>&2; }
LogshEmergency() { test "${LOGSH_LEVEL:-0}" -gt 800 || echo "$*" | awk "{print \"$(_logshRFC3339) [${LOGSH_COLOR:+\\033[0;1;41m}EMERGENCY${LOGSH_COLOR:+\\033[0m}] \"\$0\"\"}" 1>&2; }
LogshExec() { LogshInfo "$ $(_logshCmd "$@")" && "$@"; }

TARGET="${1:?Usage: $0 <target>}"
OS_NAME=$(uname -s)
ARCH=$(uname -m)

BIN_NAME="quicport"

# ビルド
LogshExec cargo build --release --locked --target "$TARGET"

# パッケージング
STAGE="stage/${TARGET}"
OUT="out"

LogshExec mkdir -p "${STAGE}" "${OUT}"
LogshExec cp "target/${TARGET}/release/${BIN_NAME}" "${STAGE}/"
[[ -f README.md ]] && LogshExec cp README.md "${STAGE}/"
[[ -f LICENSE ]] && LogshExec cp LICENSE "${STAGE}/"

ARCHIVE="${BIN_NAME}_${OS_NAME}_${ARCH}.zip"
(LogshExec cd "${STAGE}" && LogshExec zip -r "../../${OUT}/${ARCHIVE}" .)
LogshExec shasum -a 256 "${OUT}/${ARCHIVE}" > "${OUT}/${ARCHIVE}.sha256"

LogshInfo "Created: ${OUT}/${ARCHIVE}"
