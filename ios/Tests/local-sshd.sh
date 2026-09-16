#!/bin/bash
# Start the loopback sshd fixtures that SSHLocalServerIntegrationTests needs.
#
#   ./Tests/local-sshd.sh start     # start every server
#   ./Tests/local-sshd.sh stop      # stop them
#   ./Tests/local-sshd.sh status
#
# Every server is temporary, bound to 127.0.0.1 only, and authenticates exactly
# one throwaway key — the one committed in SSHLocalServerIntegrationTests.swift.
# The certificate fixtures (a user CA, a signed user certificate, a host key, a
# host CA and a host certificate) are committed in that same file so the tests
# are reproducible; they are written out here rather than regenerated, because
# a CA that changed on every run could not be asserted against.
#
# The iOS simulator shares the host's network stack, so 127.0.0.1 inside the
# simulator is this Mac's loopback.
set -euo pipefail

D=/tmp/ghostty-sshd
SSHD=/usr/sbin/sshd

# The throwaway key the tests authenticate with.
read -r -d '' USER_KEY <<'EOF' || true
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCTsWo2uwxUy3t0HRWet3H14UkFWiNJSr7M9Jo0mqqjewAAAKCg1HvboNR7
2wAAAAtzc2gtZWQyNTUxOQAAACCTsWo2uwxUy3t0HRWet3H14UkFWiNJSr7M9Jo0mqqjew
AAAEAt2Gmsq6Ru+Da1XiViBO0VdkG6AjJ33DfMAv+oM6QqVZOxaja7DFTLe3QdFZ63cfXh
SQVaI0lKvsz0mjSaqqN7AAAAGGdob3N0dHktaW50ZWdyYXRpb24tdGVzdAECAwQF
-----END OPENSSH PRIVATE KEY-----
EOF

USER_CA_PUB='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImwfST+6B9eCSs+DGsJJxupIECpccS0iqOISuqxEy8W ghostty-test-user-ca'

# The user certificate over the key above, signed by that CA. Written out so
# `ssh -o CertificateFile=...` can be used to check the server by hand; the app
# carries its own copy in the test file.
USER_CERT='ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIFf7DLxYNiJFwsfBZbNg6kP8Hb4e5xZvcdOtSOiG8hUHAAAAIJOxaja7DFTLe3QdFZ63cfXhSQVaI0lKvsz0mjSaqqN7AAAAAAAAEJIAAAABAAAAE2dob3N0dHktaW50ZWdyYXRpb24AAAAQAAAADGFuZHJld2hheW5lcwAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACCJsH0k/ugfXgkrPgxrCScbqSBAqXHEtIqjiErqsRMvFgAAAFMAAAALc3NoLWVkMjU1MTkAAABAGcBkdsEd7GOOlNw0IeFtjpqCUq/GGNENBpfI21VjL0Lh6E6dvrOjAR54Hvn8MyGYrRICmI3GMgj/+NCtBLsWCg== ghostty-integration-test'
HOST_CA_PUB='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICtMkuaRK1TLWooscoH475JlCmIYN9Bwa60toMtUAVGY ghostty-test-host-ca'

read -r -d '' HOST_KEY <<'EOF' || true
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB8Zf/XxEexVbOpvwLLrNARH0QJKbR9yuZgZuLY/G0NjgAAAJixxGfIscRn
yAAAAAtzc2gtZWQyNTUxOQAAACB8Zf/XxEexVbOpvwLLrNARH0QJKbR9yuZgZuLY/G0Njg
AAAEAxe2/3+jxyPNtpUjnCwEDVK60J/mNQTtZexslDkSs3znxl/9fER7FVs6m/Asus0BEf
RAkptH3K5mBm4tj8bQ2OAAAAEWdob3N0dHktdGVzdC1ob3N0AQIDBA==
-----END OPENSSH PRIVATE KEY-----
EOF

HOST_CERT='ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIM311T0X0pzSBYwgFCRfn/drKM42hJ9Jb7Hu/giKjciAAAAAIHxl/9fER7FVs6m/Asus0BEfRAkptH3K5mBm4tj8bQ2OAAAAAAAAAAcAAAACAAAAFWdob3N0dHktbG9vcGJhY2staG9zdAAAABoAAAAJMTI3LjAuMC4xAAAACWxvY2FsaG9zdAAAAAAAAAAA//////////8AAAAAAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAICtMkuaRK1TLWooscoH475JlCmIYN9Bwa60toMtUAVGYAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEAxB5y3+LGn45bK7vubw8pZyd5SnIGalmVBCzhm5l2vKIxDOvVTwtpfeqWYaqn4b5n68uQ1LCfdQzUL6cxRwvcL ghostty-test-host'

# NOTE: sshd takes the *first* occurrence of a keyword, not the last, so
# anything a single server overrides has to be written before this block.
common_config() {
  cat <<EOF
ListenAddress 127.0.0.1
AuthorizedKeysFile $D/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PrintMotd no
LogLevel VERBOSE
EOF
}

setup() {
  rm -rf "$D"
  mkdir -p "$D"
  chmod 700 "$D"

  printf '%s\n' "$USER_KEY" > "$D/user_key"
  chmod 600 "$D/user_key"
  ssh-keygen -y -f "$D/user_key" > "$D/authorized_keys"
  chmod 600 "$D/authorized_keys"

  printf '%s\n' "$HOST_KEY" > "$D/host_ed25519"
  chmod 600 "$D/host_ed25519"
  printf '%s\n' "$HOST_CERT" > "$D/host_ed25519-cert.pub"

  printf '%s\n' "$USER_CA_PUB" > "$D/user_ca.pub"
  printf '%s\n' "$USER_CERT" > "$D/user_key-cert.pub"
  printf '%s\n' "$HOST_CA_PUB" > "$D/host_ca.pub"

  # The RSA-only server's host key is generated rather than committed: nothing
  # asserts its identity, only that an RSA host key can be verified at all.
  ssh-keygen -q -t rsa -b 3072 -N '' -C 'ghostty-test-host-rsa' -f "$D/host_rsa"

  # :22022 — AES-CTR with HMAC only, no AEAD anywhere. The configuration that
  # was unreachable before #008A0.
  { common_config
    echo "Port 22022"
    echo "HostKey $D/host_ed25519"
    echo "Ciphers aes256-ctr,aes192-ctr,aes128-ctr"
    echo "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256"
  } > "$D/sshd_ctr.conf"

  # :22023 — an RSA host key and nothing else, under SHA-2 signature algorithms.
  # Unverifiable before #008D0; a normal connection after it.
  { common_config
    echo "Port 22023"
    echo "HostKey $D/host_rsa"
    echo "HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256"
  } > "$D/sshd_rsa.conf"

  # :22024 — OpenSSH's own defaults. Here to prove the widened cipher list
  # cannot quietly downgrade a connection that already worked.
  { common_config
    echo "Port 22024"
    echo "HostKey $D/host_ed25519"
  } > "$D/sshd_full.conf"

  # :22025 — chacha20-poly1305@openssh.com and nothing else.
  { common_config
    echo "Port 22025"
    echo "HostKey $D/host_ed25519"
    echo "Ciphers chacha20-poly1305@openssh.com"
  } > "$D/sshd_chacha.conf"

  # :22026 — hmac-sha2-512 and nothing else, over a non-AEAD cipher so the MAC
  # is actually negotiated rather than ignored.
  { common_config
    echo "Port 22026"
    echo "HostKey $D/host_ed25519"
    echo "Ciphers aes256-ctr"
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-512"
  } > "$D/sshd_hmac512.conf"

  # :22027 — certificate user authentication. No authorized_keys at all, so the
  # only way in is a certificate signed by the test CA. `AuthorizedKeysFile none`
  # comes first on purpose: sshd keeps the first value it sees for a keyword, so
  # writing it after common_config would silently do nothing and the server would
  # admit the bare key.
  { echo "AuthorizedKeysFile none"
    echo "AuthorizedPrincipalsFile none"
    common_config
    echo "Port 22027"
    echo "HostKey $D/host_ed25519"
    echo "TrustedUserCAKeys $D/user_ca.pub"
  } > "$D/sshd_usercert.conf"

  # :22028 — the server presents a CA-signed *host* certificate.
  { common_config
    echo "Port 22028"
    echo "HostKey $D/host_ed25519"
    echo "HostCertificate $D/host_ed25519-cert.pub"
  } > "$D/sshd_hostcert.conf"
}

start() {
  setup
  for name in ctr rsa full chacha hmac512 usercert hostcert; do
    "$SSHD" -f "$D/sshd_$name.conf" -E "$D/$name.log" -D &
  done
  sleep 1
  status
}

stop() {
  pkill -f "sshd -f $D/" || true
  echo "stopped"
}

status() {
  for port in 22022 22023 22024 22025 22026 22027 22028; do
    if nc -z 127.0.0.1 "$port" 2>/dev/null; then
      echo "  :$port up"
    else
      echo "  :$port DOWN"
    fi
  done
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) echo "usage: $0 {start|stop|status}" >&2; exit 2 ;;
esac
