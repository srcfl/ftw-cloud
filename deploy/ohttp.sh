#!/bin/bash
# Give ftwcloudd the Oblivious HTTP gateway key. Run as root on the FTW Cloud host
# through SSM, once the key is in Parameter Store
# (deploy/ohttp.md). Safe to re-run.
#
# The key rests only in Parameter Store, as a SecureString under the
# account's aws/ssm key. At every boot, before Docker starts, a unit reads it
# into tmpfs, where compose.yml mounts it into the container. It is never
# written to the volume or the image, and nothing prints it. The host role
# reads it with what it already has, as for the APNs key (deploy/apns.md).
set -euo pipefail

cat > /usr/local/sbin/ftw-cloud-ohttp <<'FETCH'
#!/bin/bash
# Read the OHTTP gateway key from Parameter Store into tmpfs for ftwcloudd.
# Without the parameter ftwcloudd runs and /v1/ohttp stays off.
set -euo pipefail
export AWS_PAGER=""
umask 077
dir=/run/ftw-cloud/ohttp
install -d -m 0700 /run/ftw-cloud
new=$(mktemp -d /run/ftw-cloud/ohttp.XXXXXX)
trap 'rm -rf "$new"' EXIT
# At boot the network and the instance's credentials may lag a little.
for try in $(seq 30); do
  if err=$(aws ssm get-parameter --region eu-north-1 --name /ftw-cloud/ohttp-key --with-decryption \
      --query Parameter.Value --output text 2>&1 >"$new/ohttp.key"); then
    break
  fi
  case "$err" in *ParameterNotFound*)
    echo "no OHTTP key in Parameter Store; /v1/ohttp stays off"
    exit 0 ;;
  esac
  [ "$try" -lt 30 ] || { echo "$err" >&2; exit 1; }
  sleep 2
done
grep -q '^-----BEGIN PRIVATE KEY-----$' "$new/ohttp.key"
# ftw-cloud-own gives it to the user the image runs as, before compose starts.
chown -R 65532:65532 "$new"
chmod 0400 "$new/ohttp.key"
chmod 0500 "$new"
rm -rf "$dir"
mv "$new" "$dir"
trap - EXIT
echo "OHTTP key in place"
FETCH
chmod 0755 /usr/local/sbin/ftw-cloud-ohttp

cat > /etc/systemd/system/ftw-cloud-ohttp.service <<'UNIT'
[Unit]
Description=FTW Cloud OHTTP gateway key into tmpfs
Before=docker.service
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ftw-cloud-ohttp

[Install]
WantedBy=docker.service
UNIT

systemctl daemon-reload
systemctl enable ftw-cloud-ohttp.service
systemctl restart ftw-cloud-ohttp.service
