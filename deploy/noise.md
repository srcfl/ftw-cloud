# The Noise key phones dial

A phone reads its home at `/v1/app` over Noise IK to the service's static
X25519 key, and the app carries the public half. Without the key the service
serves boxes, and `/v1/app` answers 501. Only the owner handles the private
key: he makes it and puts it in AWS Systems Manager Parameter Store himself.
The host reads it from there into tmpfs at every boot. It is never in the
repository, the image, the volume or a log.

## 1. Make the key (owner, once)

From a checkout of this repository:

```bash
go run ./cmd/ftwcloudd keygen -noise -out /tmp/ftw-cloud-noise.key
```

It writes the private key and prints the public half (base64url, 43
characters). Keep the public half: the app needs it in step 4.

## 2. Put it in Parameter Store (owner, once)

In a terminal signed in to the FTW Cloud account (976075258475):

```bash
aws ssm put-parameter --region eu-north-1 --name /ftw-cloud/noise-key --type SecureString --value file:///tmp/ftw-cloud-noise.key
rm /tmp/ftw-cloud-noise.key
```

## 3. Give it to the host (once per host)

`deploy/noise.sh` installs `ftw-cloud-noise.service`, which reads the
parameter into `/run/ftw-cloud/noise/` (tmpfs, readable only by the
container's user) before Docker starts. `compose.yml` mounts that directory
read-only. Run it through SSM, then redeploy so a new container reads the key:

```bash
aws ssm send-command --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["bash /opt/ftw-cloud/deploy/noise.sh","/usr/local/sbin/ftw-cloud-deploy"]'
```

Then, from anywhere:

```bash
curl -s -o /dev/null -w '%{http_code}\n' 'https://cloud.ftw.energy/v1/app?home=aaaaaaaaaaaaaaaaaaaaaaaaaa'
```

It says 426 (the socket wants an upgrade) instead of 501. The start line in
the log, `ftwcloudd listening … noise_key=…`, shows the public half from
step 1.

## 4. Put the public half in the app

`CloudEndpoint.releaseKeys` in srcfl/ftw-app, `appleApp/FTWKit`, holds it.
A release build of the app dials FTW Cloud only once it is there.

## Rotating

The app carries up to two public halves and tries the next when the service
refuses message 1. Ship an app with the new public half beside the old one,
wait for phones to update, then put the new private key in place with
`put-parameter --overwrite` and run
`systemctl restart ftw-cloud-noise.service ftw-cloud.service`. Drop the old
public half in a later app release.

## Access

The host role needs nothing new, as for the APNs key: see
[apns.md](apns.md), "Access". Secrets Manager would need one more ARN in
`deploy/host-policy.json`.
