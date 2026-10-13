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

# Docker, Compose and buildx, as the relay host does it.
dnf install -y docker git
systemctl enable --now docker

install -d /usr/local/lib/docker/cli-plugins
case "$(uname -m)" in
  aarch64) PLUGIN_ARCH=arm64 ; COMPOSE_ARCH=aarch64 ;;
  *)       PLUGIN_ARCH=amd64 ; COMPOSE_ARCH=x86_64 ;;
esac
curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${COMPOSE_ARCH}" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
# sed reads to the end. head or grep -m1 closes the pipe early, and under
# pipefail that fails the script.
BUILDX_URL=$(curl -fsS https://api.github.com/repos/docker/buildx/releases/latest \
  | grep -o "https://[^\"]*linux-${PLUGIN_ARCH}" | sed -n 1p)
curl -fsSL "$BUILDX_URL" -o /usr/local/lib/docker/cli-plugins/docker-buildx
chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx
docker compose version
docker buildx version

if [ ! -d /opt/ftw-cloud ]; then
  git clone https://github.com/srcfl/ftw-cloud /opt/ftw-cloud
fi

install -d -m 0700 /var/lib/ftw-cloud /etc/ftw-cloud

# The service key rests on the encrypted root volume, readable by root only.
# At boot, before Docker starts, a copy goes to tmpfs, where compose.yml
# mounts it into the container.
cat > /etc/systemd/system/ftw-cloud-key.service <<'UNIT'
[Unit]
Description=FTW Cloud service key into tmpfs
Before=docker.service
ConditionPathExists=/var/lib/ftw-cloud/service.key

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/install -d -m 0700 /run/ftw-cloud
ExecStart=/usr/bin/install -m 0400 -o 65532 -g 65532 /var/lib/ftw-cloud/service.key /run/ftw-cloud/service.key

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

# One command updates the host: pull, build, run. The checkout's branch
# decides what runs.
cat > /usr/local/sbin/ftw-cloud-deploy <<'DEPLOY'
#!/bin/bash
# Build the commit checked out in /opt/ftw-cloud and run it. Every box
# reconnects within seconds; there is nothing to drain.
set -euo pipefail
export HOME=${HOME:-/root}
cd /opt/ftw-cloud
git pull --ff-only
rev=$(git rev-parse --short=12 HEAD)
docker build --pull -t "ftw-cloud:$rev" .

# The key is made once, on this host, and never leaves it. Its public half
# is what Core carries in cloudlink.ServiceKeys.
if [ ! -s /var/lib/ftw-cloud/service.key ]; then
  docker run --rm --user 0:0 --network none -v /var/lib/ftw-cloud:/out \
    "ftw-cloud:$rev" keygen -out /out/service.key
fi
systemctl enable ftw-cloud-key.service ftw-cloud.service
systemctl restart ftw-cloud-key.service

printf 'FTW_CLOUD_IMAGE=ftw-cloud:%s\n' "$rev" > /etc/ftw-cloud/compose.env
cd deploy
# Always a new container. A file mounted on its own, such as the key, keeps
# the copy the container started with even after the file on the host
# changes; only a new container reads it again.
docker compose --env-file /etc/ftw-cloud/compose.env up -d --force-recreate

for img in $(docker image ls ftw-cloud --format '{{.Repository}}:{{.Tag}}'); do
  [ "$img" = "ftw-cloud:$rev" ] || docker image rm "$img"
done
docker image prune -f
docker builder prune -f --filter until=168h
echo "ftw-cloud:$rev running"
DEPLOY
chmod 0755 /usr/local/sbin/ftw-cloud-deploy

systemctl daemon-reload
/usr/local/sbin/ftw-cloud-deploy

# Show that the host rules hold.
swapon --show
sysctl kernel.core_pattern
docker compose --env-file /etc/ftw-cloud/compose.env -f /opt/ftw-cloud/deploy/compose.yml ps
