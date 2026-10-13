#!/bin/bash
# Give ftwcloudd the Noise key phones dial. Run as root on the FTW Cloud host
# through SSM, once the key is in Parameter Store
# (deploy/noise.md). Safe to re-run.
#
# The key rests only in Parameter Store, as a SecureString under the
# account's aws/ssm key. At every boot, before Docker starts, a unit reads it
# into tmpfs, where compose.yml mounts it into the container. It is never
# written to the volume or the image, and nothing prints it. The host role
# reads it with what it already has, as for the APNs key (deploy/apns.md).
set -euo pipefail

cat > /usr/local/sbin/ftw-cloud-noise <<'FETCH'
#!/bin/bash
# Read the Noise key from Parameter Store into tmpfs for ftwcloudd.
# Without the parameter ftwcloudd runs and /v1/app stays off.
set -euo pipefail
export AWS_PAGER=""
umask 077
dir=/run/ftw-cloud/noise
install -d -m 0700 /run/ftw-cloud
new=$(mktemp -d /run/ftw-cloud/noise.XXXXXX)
trap 'rm -rf "$new"' EXIT
# At boot the network and the instance's credentials may lag a little.
for try in $(seq 30); do
  if err=$(aws ssm get-parameter --region eu-north-1 --name /ftw-cloud/noise-key --with-decryption \
      --query Parameter.Value --output text 2>&1 >"$new/noise.key"); then
    break
  fi
  case "$err" in *ParameterNotFound*)
    echo "no Noise key in Parameter Store; /v1/app stays off"
    exit 0 ;;
  esac
  [ "$try" -lt 30 ] || { echo "$err" >&2; exit 1; }
  sleep 2
done
grep -q '^-----BEGIN PRIVATE KEY-----$' "$new/noise.key"
chown -R 65532:65532 "$new"
chmod 0400 "$new/noise.key"
chmod 0500 "$new"
rm -rf "$dir"
mv "$new" "$dir"
trap - EXIT
echo "Noise key in place"
FETCH
chmod 0755 /usr/local/sbin/ftw-cloud-noise

cat > /etc/systemd/system/ftw-cloud-noise.service <<'UNIT'
[Unit]
Description=FTW Cloud Noise key into tmpfs
Before=docker.service
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ftw-cloud-noise

[Install]
WantedBy=docker.service
UNIT

systemctl daemon-reload
systemctl enable ftw-cloud-noise.service
systemctl restart ftw-cloud-noise.service
