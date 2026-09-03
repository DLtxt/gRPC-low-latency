# Shared helpers for the benchmark scripts. Source, do not execute.

# Locate libsofthsm2 without assuming a platform. Homebrew keeps the .so name on
# macOS; Debian and Amazon Linux differ in directory and in lib vs lib64.
find_pkcs11_module() {
    if [ -n "${PKCS11_MODULE:-}" ]; then printf '%s' "${PKCS11_MODULE}"; return; fi
    for candidate in \
        /opt/homebrew/lib/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so \
        /usr/lib/*/softhsm/libsofthsm2.so
    do
        [ -f "${candidate}" ] && { printf '%s' "${candidate}"; return; }
    done
    echo "ERROR: could not locate libsofthsm2.so; set PKCS11_MODULE" >&2
    return 1
}

# lsof is not installed on minimal cloud images, and neither is ss on some, so fall
# back to a bare TCP connect. The check is not optional: benchmarking a stale process
# that happens to hold the port silently produces numbers for the wrong binary.
port_in_use() {
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
    elif command -v ss >/dev/null 2>&1; then
        ss -ltnH "sport = :$1" 2>/dev/null | grep -q .
    else
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3<&- 3>&-; return 0; }
        return 1
    fi
}
