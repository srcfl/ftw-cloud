#!/bin/bash
# Give ftwcloudd Apple's push key. Run as root on the FTW Cloud host through
# SSM, after the owner has put the key in Parameter Store (deploy/apns.md).
# Safe to re-run.
#
# The key rests only in Parameter Store, as a SecureString under the
# account's aws/ssm key. At every boot, before Docker starts, a unit reads it
# into tmpfs, where compose.yml mounts it into the container. It is never
# written to the volume or the image, and nothing prints it.
#
# The host role reads it with what it already has: AmazonSSMManagedInstanceCore
# allows ssm:GetParameter, and the aws/ssm key's policy allows decrypting
# through SSM for every principal in the account. No IAM change is needed.
set -euo pipefail

cat > /usr/local/sbin/ftw-cloud-apns <<'FETCH'
#!/bin/bash
# Read Apple's push key from Parameter Store into tmpfs for ftwcloudd.
# Without the parameters ftwcloudd runs and sends no alerts.
set -euo pipefail
export AWS_PAGER=""
umask 077
dir=/run/ftw-cloud/apns
install -d -m 0700 /run/ftw-cloud
new=$(mktemp -d /run/ftw-cloud/apns.XXXXXX)
trap 'rm -rf "$new"' EXIT
# get NAME FILE: 0 when read, 1 when the parameter does not exist. At boot
# the network and the instance's credentials may lag a little.
get() {
  local err
  for try in $(seq 30); do
    if err=$(aws ssm get-parameter --region eu-north-1 --name "$1" --with-decryption \
        --query Parameter.Value --output text 2>&1 >"$new/$2"); then
      return 0
    fi
    case "$err" in *ParameterNotFound*) return 1 ;; esac
    [ "$try" -lt 30 ] || { echo "$err" >&2; exit 1; }
    sleep 2
  done
}
if ! get /ftw-cloud/apns/key key.p8 || ! get /ftw-cloud/apns/key-id key-id || ! get /ftw-cloud/apns/team-id team-id; then
  echo "no APNs key in Parameter Store; ftwcloudd will send no alerts"
  exit 0
fi
grep -q '^-----BEGIN PRIVATE KEY-----$' "$new/key.p8"
chown -R 65532:65532 "$new"
chmod 0400 "$new"/*
chmod 0500 "$new"
rm -rf "$dir"
mv "$new" "$dir"
trap - EXIT
echo "APNs key in place"
FETCH
chmod 0755 /usr/local/sbin/ftw-cloud-apns

cat > /etc/systemd/system/ftw-cloud-apns.service <<'UNIT'
[Unit]
Description=FTW Cloud APNs key into tmpfs
Before=docker.service
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ftw-cloud-apns

[Install]
WantedBy=docker.service
UNIT

systemctl daemon-reload
systemctl enable ftw-cloud-apns.service
systemctl restart ftw-cloud-apns.service
