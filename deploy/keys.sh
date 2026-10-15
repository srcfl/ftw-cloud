#!/bin/bash
# Prepare the FTW Cloud host for ftwkeysd, the keys part. Run as root on the
# host through SSM, after the two KMS keys and the keys role exist
# (deploy/keys.md). Safe to re-run.
#
# It makes the socket's directory at every boot, keeps short-lived
# credentials of the keys role in tmpfs for ftwkeysd, and turns ftwkeysd on
# in compose.env. It touches no AWS resource.
set -euo pipefail
agent_key="${1:?usage: keys.sh <agent KMS key ARN> <offer KMS key ARN>}"
offer_key="${2:?usage: keys.sh <agent KMS key ARN> <offer KMS key ARN>}"
for arn in "$agent_key" "$offer_key"; do
  case "$arn" in
    arn:aws:kms:eu-north-1:*:key/*) ;;
    *) echo "not a KMS key ARN in eu-north-1: $arn" >&2; exit 1 ;;
  esac
done

# ftwkeysd runs as 65533 in ftwcloudd's group, 65530. The directory is the
# only way to the socket: ftwcloudd may enter it and connect, and nothing
# else on the host but root may.
cat > /etc/tmpfiles.d/ftw-cloud-keys.conf <<'TMPFILES'
d /run/ftw-cloud-keys 0750 65533 65530 -
d /run/ftw-cloud-keys-aws 0700 65533 65533 -
TMPFILES
systemd-tmpfiles --create /etc/tmpfiles.d/ftw-cloud-keys.conf

# No container reaches the instance's credentials (hop limit 1), and the
# instance role may do more than ftwkeysd needs. So the host assumes the
# keys role, which may only use the two KMS keys, and leaves its credentials
# for ftwkeysd in tmpfs. They last an hour and are renewed every 15 minutes.
cat > /usr/local/sbin/ftw-cloud-keys-aws <<'FETCH'
#!/bin/bash
# The keys role's credentials into tmpfs for ftwkeysd.
set -euo pipefail
export AWS_PAGER=""
umask 077
dir=/run/ftw-cloud-keys-aws
install -d -m 0700 -o 65533 -g 65533 "$dir"
tmp=$(mktemp "$dir/.credentials.XXXXXX")
trap 'rm -f "$tmp"' EXIT
# At boot the network and the instance's credentials may lag a little.
for try in $(seq 30); do
  if aws sts assume-role --region eu-north-1 \
      --role-arn arn:aws:iam::976075258475:role/ftw-cloud-keys \
      --role-session-name ftwkeysd --duration-seconds 3600 \
      --query Credentials --output json >"$tmp"; then
    break
  fi
  [ "$try" -lt 30 ] || exit 1
  sleep 2
done
chown 65533:65533 "$tmp"
chmod 0400 "$tmp"
mv -f "$tmp" "$dir/credentials.json"
trap - EXIT
FETCH
chmod 0755 /usr/local/sbin/ftw-cloud-keys-aws

cat > /etc/systemd/system/ftw-cloud-keys-aws.service <<'UNIT'
[Unit]
Description=FTW Cloud keys role credentials into tmpfs for ftwkeysd
Wants=network-online.target
After=network-online.target
Before=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ftw-cloud-keys-aws

[Install]
WantedBy=docker.service
UNIT

cat > /etc/systemd/system/ftw-cloud-keys-aws.timer <<'UNIT'
[Unit]
Description=Renew the FTW Cloud keys role credentials

[Timer]
OnActiveSec=15min
OnUnitActiveSec=15min
AccuracySec=1min

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable ftw-cloud-keys-aws.service
systemctl enable --now ftw-cloud-keys-aws.timer
systemctl start ftw-cloud-keys-aws.service

env=/etc/ftw-cloud/compose.env
touch "$env"
sed -i '/^FTW_CLOUD_KMS_KEY=/d; /^FTW_CLOUD_OFFER_KEY=/d; /^COMPOSE_PROFILES=/d' "$env"
printf 'FTW_CLOUD_KMS_KEY=%s\nFTW_CLOUD_OFFER_KEY=%s\nCOMPOSE_PROFILES=agents\n' "$agent_key" "$offer_key" >> "$env"
echo "ftwkeysd is on; the next ftw-cloud-deploy (or a restart of ftw-cloud.service) starts it"
