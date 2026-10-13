# Apple's push key

`ftwcloudd` sends alerts through APNs with a token key (`.p8`) from Sourceful's
Apple team. Only the owner handles the key: he makes it at Apple and puts it
in AWS Systems Manager Parameter Store himself. The host reads it from there
into tmpfs at every boot. It is never in the repository, the image, the volume
or a log.

## 1. Make the key (owner, once)

1. [developer.apple.com/account](https://developer.apple.com/account) →
   Certificates, Identifiers & Profiles → **Keys** → **+**.
2. Name it `FTW Cloud APNs`, tick **Apple Push Notifications service (APNs)**,
   and choose **Configure**: environment **Sandbox & Production**; key
   restriction **Topic Specific** with `energy.ftw.app`, or **Team Scoped**.
   Save, then **Continue** → **Register**.
3. **Download** `AuthKey_<KEYID>.p8`. Apple lets you download it once. Note the
   10-character **Key ID**. The Team ID is `L66M368PZ6`.
4. Under **Identifiers** → `energy.ftw.app`, check that **Push Notifications**
   and **Time Sensitive Notifications** are on. Xcode turns them on the first
   time it signs the app with the new entitlements.

## 2. Put it in Parameter Store (owner, once)

In a terminal signed in to the FTW Cloud account (976075258475), with the
file where Safari saved it:

```bash
aws ssm put-parameter --region eu-north-1 --name /ftw-cloud/apns/key --type SecureString --value "file://$HOME/Downloads/AuthKey_KEYID.p8"
aws ssm put-parameter --region eu-north-1 --name /ftw-cloud/apns/key-id --type String --value KEYID
aws ssm put-parameter --region eu-north-1 --name /ftw-cloud/apns/team-id --type String --value L66M368PZ6
```

Then keep the `.p8` in the password manager or delete it. A new key replaces
an old one with `--overwrite`; revoke the old one at Apple afterwards.

## 3. Give it to the host (once per host)

`deploy/apns.sh` installs `ftw-cloud-apns.service`, which reads the three
parameters into `/run/ftw-cloud/apns/` (tmpfs, readable only by the
container's user) before Docker starts. `compose.yml` mounts that directory
read-only. Run it through SSM, then redeploy so a new container mounts the
key:

```bash
aws ssm send-command --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["bash /opt/ftw-cloud/deploy/apns.sh","/usr/local/sbin/ftw-cloud-deploy"]'
```

The log then has no `APNs off` line. Without the parameters the service runs
and sends no alerts.

## Access

The host role needs nothing new. `AmazonSSMManagedInstanceCore` allows
`ssm:GetParameter` on every parameter, and the account's `aws/ssm` key allows
decrypting through SSM for every principal in the account. Checked on
2026-10-13 with `iam simulate-principal-policy` (`ssm:GetParameter` allowed)
and the key policy of `alias/aws/ssm` in eu-north-1. Secrets Manager would
need a policy change; Parameter Store does not.

srcfl/ftw-cloud#3 moves the service key to Secrets Manager with an inline
policy for that one secret. The APNs key could follow it there: one more ARN
in `deploy/host-policy.json`, applied by the owner, and `get-secret-value`
in `apns.sh`. Nothing else changes.
