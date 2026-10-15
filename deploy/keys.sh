#!/bin/bash
# Prepare the FTW Cloud host for ftwkeysd, the keys part. Run as root on the
# host through SSM, after the KMS key exists (deploy/keys.md). Safe to re-run.
#
# It makes the socket's directory at every boot, owned by ftwkeysd's user
# and readable by ftwcloudd's group, and turns ftwkeysd on in compose.env.
# It touches no AWS resource.
set -euo pipefail
key_arn="${1:?usage: keys.sh <KMS key ARN>}"
case "$key_arn" in
  arn:aws:kms:eu-north-1:*:key/*) ;;
  *) echo "not a KMS key ARN in eu-north-1: $key_arn" >&2; exit 1 ;;
esac

# ftwkeysd runs as 65533 in ftwcloudd's group, 65532. The directory is the
# only way to the socket: ftwcloudd may enter it and connect, and nothing
# else on the host but root may.
cat > /etc/tmpfiles.d/ftw-cloud-keys.conf <<'TMPFILES'
d /run/ftw-cloud-keys 0750 65533 65532 -
TMPFILES
systemd-tmpfiles --create /etc/tmpfiles.d/ftw-cloud-keys.conf

env=/etc/ftw-cloud/compose.env
touch "$env"
sed -i '/^FTW_CLOUD_KMS_KEY=/d; /^COMPOSE_PROFILES=/d' "$env"
printf 'FTW_CLOUD_KMS_KEY=%s\nCOMPOSE_PROFILES=agents\n' "$key_arn" >> "$env"
echo "ftwkeysd is on; the next ftw-cloud-deploy (or a restart of ftw-cloud.service) starts it"
