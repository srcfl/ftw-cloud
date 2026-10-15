# The keys part

`ftwkeysd` is the one process in FTW Cloud that can act on a home. It holds
each assistant's agent key, an X25519 Noise static key that a home's owner
approved, and it is the only process that can open that agent's Noise session
to the box. `ftwcloudd` carries the session's messages as `tun` through the
box's uplink, as it does a phone's, and cannot read or forge them.

Nothing here has run on the host. The owner creates the AWS resources below
and turns `ftwkeysd` on.

## Shape

| | `ftwcloudd` | `ftwkeysd` |
|---|---|---|
| User | 65532 (`nonroot`) | 65533, group 65532 |
| Network | bridge, 443 published | the host's, listens on nothing |
| Reaches | boxes, phones, assistants | KMS, through the instance role |
| State | `ftw-cloud-state` (registry, OAuth token hashes) | `ftw-cloud-keys` (sealed agent keys) |
| Socket | connects to `/run/ftw-cloud-keys/keys.sock` | owns it, mode 0660, checks the peer's uid |

- **One KMS key wraps the data keys.** Each agent key has its own AES-256 data
  key from `kms:GenerateDataKey`, and the agent key is sealed with it by
  AES-GCM. The encryption context names the purpose (`ftw-agent-key`) and the
  key id, so a wrapped data key opens only for its own agent key.
- **A key is unsealed only to open a session.** `kms:Decrypt` runs once per
  session. The secret is wiped after handshake message 1. The session's
  transport keys stay in `ftwkeysd` until the session ends: `ftwcloudd` closes
  a warm session after a short idle time, and `ftwkeysd` closes any session
  idle for 10 minutes.
- **A key waits for approval.** Each authorize request makes a key under
  `pending/`. It opens no session until the owner approves the agent and the
  box's signed roster lists it; then it moves to `kept/`. An unapproved key is
  deleted after an hour.
- **Revoking deletes the key.** When the box's roster drops an agent, or it
  expires, `ftwcloudd` asks `ftwkeysd` to forget the key, which ends its
  sessions too.
- **The offer key.** One P-256 key signs every grant offer the consent page
  hands the owner's app, so the app can tell an offer from FTW Cloud from a
  copy. It is made at the first start, sealed like an agent key (its data
  key's context names `offer-key`), and kept in memory while `ftwkeysd`
  runs. It signs only arrays that start with `ftw.offer.v1`. Core and the
  apps pin it by its kid, the first 16 characters of the base64url SHA-256
  of its public half. `ftwkeysd` logs both when it makes the key,
  `ftwkeysd offerkey` prints them, and `ftwcloudd` serves them at
  `/.well-known/ftw-offer-key`. Losing the volume makes a new offer key,
  which Core and the apps must then pin beside the old one.
- **Nothing logs a key.** Errors on the socket are a few fixed words.
- **The volume is not backed up.** Losing it means every assistant must be
  approved again; no home is exposed by it.

### Only `ftwkeysd` reaches KMS

The instance role can call KMS, so the separation rests on who can reach the
role's credentials. The instance metadata service answers IMDSv2 token
requests one network hop away when the hop limit is 1. A container on Docker's
bridge network is two hops away and gets no credentials; `ftwkeysd` uses the
host's network and gets them. `ftwcloudd` needs no AWS credentials: the host
fetches its secrets before Docker starts.

The KMS key's policy lets only the host role use it, and only with the
`ftw-agent-key` purpose. The account root can administer the key but not use
it, so another role in the shared account cannot be granted decrypt by IAM
alone.

If the cloud is fully broken into, the attacker can act as the existing
agents, within the limits their boxes enforce, until the owners revoke them
or they expire. The attacker cannot act on a home without an agent, and
cannot read the apps' sessions with their boxes.

## Turning it on

1. **The KMS key** (once, from a workstation with admin rights):

   ```bash
   key=$(aws kms create-key --region eu-north-1 \
     --description 'FTW Cloud agent keys (ftwkeysd)' \
     --key-spec SYMMETRIC_DEFAULT --key-usage ENCRYPT_DECRYPT \
     --policy file://deploy/keys-kms-policy.json \
     --tags TagKey=Project,TagValue=ftw-cloud \
     --query KeyMetadata.Arn --output text)
   aws kms create-alias --region eu-north-1 --alias-name alias/ftw-cloud-agent-keys \
     --target-key-id "$key"
   aws kms enable-key-rotation --region eu-north-1 --key-id "$key"
   echo "$key"
   ```

2. **The role's policy.** Put the key's id into
   [`keys-host-policy.json`](keys-host-policy.json) in place of `KEY-ID`, then:

   ```bash
   aws iam put-role-policy --role-name ftw-cloud-host --policy-name ftw-cloud-agent-keys \
     --policy-document file://deploy/keys-host-policy.json
   ```

3. **One hop to the metadata service**, so no bridged container gets the
   role's credentials:

   ```bash
   aws ec2 modify-instance-metadata-options --region eu-north-1 \
     --instance-id i-0ecac4cbc6b5f8adc --http-tokens required \
     --http-put-response-hop-limit 1
   ```

   Check from the host that a bridged container is refused:
   `docker run --rm curlimages/curl -s -m 3 -X PUT
   http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60'`
   must time out or fail.

4. **The host.** Through SSM, with the key's ARN:

   ```bash
   aws ssm send-command --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc \
     --document-name AWS-RunShellScript \
     --parameters "$(jq -n --rawfile s deploy/keys.sh --arg k "$key" \
       '{commands: ["set -- \($k)", $s]}')"
   ```

   SSM runs the lines as one script, so `set --` hands the script its
   argument. It makes `/run/ftw-cloud-keys` at every boot and sets
   `FTW_CLOUD_KMS_KEY` and `COMPOSE_PROFILES=agents` in
   `/etc/ftw-cloud/compose.env`.

5. **Deploy** as usual (`ftw-cloud-deploy sha256:<digest>`). Compose starts
   `ftwkeysd` beside `ftwcloudd`. Its log says `ftwkeysd listening`, and on
   its first start, `made the offer key` with the kid and public half.

6. **Pin the offer key** in Core and the apps (srcfl/ftw `docs/agents.md`,
   "The grant offer"): until a build pins it, no offer opens. Read it from
   `https://cloud.ftw.energy/.well-known/ftw-offer-key` or the log.

To turn assistants off again, remove `COMPOSE_PROFILES=agents` and deploy.
Approved agents stay sealed in the volume and work again when it comes back,
unless their owners revoked them meanwhile.

## Development

```bash
go run ./cmd/ftwkeysd filekey -out dev-keys.key
go run ./cmd/ftwkeysd -socket /tmp/ftwkeys/keys.sock -state /tmp/ftwkeys/state -file-key dev-keys.key
```

A file key is for development only: whoever reads it and the state directory
has every agent key.
