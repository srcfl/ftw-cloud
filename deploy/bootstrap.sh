#!/bin/bash
# Bring up an FTW Cloud host. Amazon Linux 2023, arm64, run as root through
# SSM. Safe to re-run: everything below is idempotent, and a re-run is also
# how the host's own tooling gets updated.
set -euxo pipefail

export HOME=${HOME:-/root}

# Readings live only in ftwcloudd's memory. No swap may page them to disk and
# no core file may carry them out.
swapoff -a
sed -i '/\sswap\s/d' /etc/fstab
cat > /etc/sysctl.d/99-ftw-cloud.conf <<'SYSCTL'
kernel.core_pattern = |/bin/false
fs.suid_dumpable = 0
SYSCTL
sysctl --system >/dev/null
install -d /etc/systemd/coredump.conf.d
printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/ftw-cloud.conf
printf '* hard core 0\n' > /etc/security/limits.d/ftw-cloud.conf

# No SSH, not even behind the security group. Administration is through SSM.
# cloud-init wants sshd at every boot, so disabling it is not enough.
systemctl mask --now sshd.service

# Docker and Compose. The host builds nothing: CI builds the image.
dnf install -y docker git awscli-2
systemctl enable --now docker

install -d /usr/local/lib/docker/cli-plugins
case "$(uname -m)" in
  aarch64) COMPOSE_ARCH=aarch64 ;;
  *)       COMPOSE_ARCH=x86_64 ;;
esac
curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${COMPOSE_ARCH}" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version

# The checkout supplies compose.yml. ftw-cloud-deploy moves it to the commit
# the running image was built from.
if [ ! -d /opt/ftw-cloud ]; then
  git clone https://github.com/srcfl/ftw-cloud /opt/ftw-cloud
fi

install -d -m 0700 /etc/ftw-cloud

# The service key lives in Secrets Manager. At boot, before Docker starts,
# it comes into tmpfs, where compose.yml mounts it into the container. It is
# never on disk.
cat > /usr/local/sbin/ftw-cloud-key <<'KEY'
#!/bin/bash
# Fetch the service key from Secrets Manager into /run/ftw-cloud (tmpfs).
set -euo pipefail
export AWS_PAGER=""
umask 077
install -d -m 0700 /run/ftw-cloud
tmp=$(mktemp /run/ftw-cloud/service.key.XXXXXX)
trap 'rm -f "$tmp"' EXIT
# At boot the network and the instance's credentials may lag a little.
for try in $(seq 30); do
  if aws secretsmanager get-secret-value --region eu-north-1 \
      --secret-id ftw-cloud/service-key --query SecretString --output text >"$tmp"; then
    break
  fi
  [ "$try" -lt 30 ] || exit 1
  sleep 2
done
grep -q '^-----BEGIN EC PRIVATE KEY-----$' "$tmp"
chown 65532:65532 "$tmp"
chmod 0400 "$tmp"
mv -f "$tmp" /run/ftw-cloud/service.key
KEY
chmod 0755 /usr/local/sbin/ftw-cloud-key

cat > /etc/systemd/system/ftw-cloud-key.service <<'UNIT'
[Unit]
Description=FTW Cloud service key from Secrets Manager into tmpfs
Wants=network-online.target
After=network-online.target
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ftw-cloud-key

[Install]
WantedBy=docker.service
UNIT

# Come back after a reboot without anyone logging in.
cat > /etc/systemd/system/ftw-cloud.service <<'UNIT'
[Unit]
Description=FTW Cloud
Requires=docker.service ftw-cloud-key.service
After=docker.service ftw-cloud-key.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/ftw-cloud/deploy
ExecStart=/usr/bin/docker compose --env-file /etc/ftw-cloud/compose.env up -d
ExecStop=/usr/bin/docker compose --env-file /etc/ftw-cloud/compose.env down

[Install]
WantedBy=multi-user.target
UNIT

# One command updates the host to an image CI built, named by its digest.
cat > /usr/local/sbin/ftw-cloud-deploy <<'DEPLOY'
#!/bin/bash
# Run an image CI built, named by its digest:
#
#   ftw-cloud-deploy sha256:<64 hex>
#
# The Image workflow's run on main shows the digest. With no argument, it
# runs the digest in /etc/ftw-cloud/compose.env again. Every box reconnects
# within seconds; there is nothing to drain.
set -euo pipefail
export HOME=${HOME:-/root}
repo=ghcr.io/srcfl/ftw-cloud
env=/etc/ftw-cloud/compose.env

digest=${1:-$(sed -n "s|^FTW_CLOUD_IMAGE=$repo@||p" "$env" 2>/dev/null || true)}
if ! [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "usage: ftw-cloud-deploy sha256:<64 hex>" >&2
  exit 2
fi
image=$repo@$digest
docker pull --quiet "$image"

# Run only what CI built from main, and take compose.yml from that same
# commit, so the two cannot drift apart.
rev=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
cd /opt/ftw-cloud
git fetch --quiet origin main
if ! [[ $rev =~ ^[0-9a-f]{40}$ ]] || ! git merge-base --is-ancestor "$rev" origin/main; then
  echo "$image was not built from a commit on main" >&2
  exit 1
fi
git checkout --quiet --detach "$rev"

# Fetch the key again, so a new version in Secrets Manager takes effect.
systemctl restart ftw-cloud-key.service

printf 'FTW_CLOUD_IMAGE=%s\n' "$image" > "$env"
cd deploy
# Always a new container. A file mounted on its own, such as the key, keeps
# the copy the container started with even after the file on the host
# changes; only a new container reads it again.
docker compose --env-file "$env" up -d --force-recreate
docker image prune --all --force >/dev/null
echo "$image running, built from $rev"
DEPLOY
chmod 0755 /usr/local/sbin/ftw-cloud-deploy

systemctl daemon-reload
systemctl enable ftw-cloud-key.service ftw-cloud.service

# Show that the host rules hold.
swapon --show
sysctl kernel.core_pattern

# A host that already runs an image from CI runs it again with the new
# tooling. A new host waits for the owner to name a digest.
if grep -q '^FTW_CLOUD_IMAGE=ghcr.io/srcfl/ftw-cloud@sha256:' /etc/ftw-cloud/compose.env 2>/dev/null; then
  /usr/local/sbin/ftw-cloud-deploy
  docker compose --env-file /etc/ftw-cloud/compose.env -f /opt/ftw-cloud/deploy/compose.yml ps
else
  echo "Next: ftw-cloud-deploy sha256:<digest from the Image workflow on main>"
fi
