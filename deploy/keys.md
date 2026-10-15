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
| User | 65530, its own (not distroless's shared `nonroot`) | 65533, group 65530 |
| Network | the default bridge, 443 published | a bridge of its own, listens on nothing |
| Reaches | boxes, phones, assistants | KMS, as the `ftw-cloud-keys` role |
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
  sessions too. `ftwcloudd` keeps asking, across restarts, until `ftwkeysd`
  has done it.
- **A second KMS key signs offers.** The consent page hands the owner's app a
  grant offer, and the app must tell an offer from FTW Cloud from a copy. An
  asymmetric KMS key (`ECC_NIST_P256`, `SIGN_VERIFY`) signs every offer with
  `kms:Sign`; its private half never leaves KMS. `ftwkeysd` signs only an
  offer it can vouch for: a well-formed offer for the agent role, good for at
  most ten minutes, whose key is one that `ftwkeysd` made and that waits for
  approval. So `ftwcloudd` cannot get an owner to approve a key `ftwcloudd`
  holds. Core and the apps pin the offer key by its kid, the first 16
  characters of the base64url SHA-256 of its public half.
- **Nothing logs a key.** Errors on the socket are a few fixed words.
- **The volume is not backed up.** Losing it means every assistant must be
  approved again; no home is exposed by it.

A production build of `ftwkeysd` has no file key and no local offer key. A
development build (`-tags ftwclouddev`) has both; see Development below.

### Only `ftwkeysd` reaches KMS, and it reaches nothing else

The instance role reads the service key and the parameters at boot, so no
container may hold its credentials. The instance metadata service answers
IMDSv2 token requests one network hop away when the hop limit is 1; every
container sits on a Docker bridge, two hops away, and gets nothing.

`ftwkeysd` uses a role of its own, `ftw-cloud-keys`, which may use the two KMS
keys and nothing else. The host assumes it every 15 minutes and leaves the
hour-long credentials in tmpfs, readable only by `ftwkeysd`'s user, which
mounts them read-only.

Each KMS key's policy lets only `ftw-cloud-keys` use it: the agent key only
with the `ftw-agent-key` purpose, the offer key only to sign SHA-256 digests
and read its public half. An explicit deny on `kms:CreateGrant` means no grant
opens either key beside its policy. The account root may administer the keys
but not use them, so another role in the shared account gains nothing from
IAM alone. This guards against mistakes; it is not a wall: whoever may put a
key's policy (`kms:PutKeyPolicy`) can write themselves in, and that change
shows in CloudTrail.

If the cloud is fully broken into, the attacker can act as the existing
agents, within the limits their boxes enforce, until the owners revoke them
or they expire. The attacker cannot act on a home without an agent, and
cannot read the apps' sessions with their boxes.

## Turning it on

0. **The host's tooling.** This image runs `ftwcloudd` as 65530, and
   `ftw-cloud-deploy` now keeps the lines `keys.sh` adds to `compose.env`.
   Re-run [`bootstrap.sh`](bootstrap.sh) through SSM before deploying it; it
   installs `ftw-cloud-own`, which gives `ftwcloudd`'s state and secrets to
   the user its image runs as at every start, so deploying this image, or
   going back to an older one, finds its files its own.

1. **The keys role** (once, from a workstation with admin rights):

   ```bash
   aws iam create-role --role-name ftw-cloud-keys \
     --assume-role-policy-document file://deploy/keys-role-trust.json \
     --max-session-duration 3600 --tags Key=Project,Value=ftw-cloud
   aws iam put-role-policy --role-name ftw-cloud-host --policy-name ftw-cloud-keys-assume \
     --policy-document file://deploy/keys-host-policy.json
   ```

2. **The two KMS keys:**

   ```bash
   agent=$(aws kms create-key --region eu-north-1 \
     --description 'FTW Cloud agent keys (ftwkeysd)' \
     --key-spec SYMMETRIC_DEFAULT --key-usage ENCRYPT_DECRYPT \
     --policy file://deploy/keys-kms-policy.json \
     --tags TagKey=Project,TagValue=ftw-cloud \
     --query KeyMetadata.Arn --output text)
   aws kms create-alias --region eu-north-1 --alias-name alias/ftw-cloud-agent-keys \
     --target-key-id "$agent"
   aws kms enable-key-rotation --region eu-north-1 --key-id "$agent"

   offer=$(aws kms create-key --region eu-north-1 \
     --description 'FTW Cloud grant offers (ftwkeysd)' \
     --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
     --policy file://deploy/keys-offer-kms-policy.json \
     --tags TagKey=Project,TagValue=ftw-cloud \
     --query KeyMetadata.Arn --output text)
   aws kms create-alias --region eu-north-1 --alias-name alias/ftw-cloud-offer-key \
     --target-key-id "$offer"
   echo "$agent $offer"
   ```

   An asymmetric key does not rotate. A new offer key is a new key, pinned
   beside the old one until every build has it.

3. **The role's policy.** Put the two keys' ids into
   [`keys-role-policy.json`](keys-role-policy.json) in place of `AGENT-KEY-ID`
   and `OFFER-KEY-ID`, then:

   ```bash
   aws iam put-role-policy --role-name ftw-cloud-keys --policy-name ftw-cloud-keys \
     --policy-document file://deploy/keys-role-policy.json
   ```

4. **One hop to the metadata service**, so no container gets the instance
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

5. **The host.** Through SSM, with both keys' ARNs:

   ```bash
   aws ssm send-command --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc \
     --document-name AWS-RunShellScript \
     --parameters "$(jq -n --rawfile s deploy/keys.sh --arg a "$agent" --arg o "$offer" \
       '{commands: ["set -- \($a) \($o)", $s]}')"
   ```

   SSM runs the lines as one script, so `set --` hands the script its
   arguments. It makes `/run/ftw-cloud-keys` at every boot, installs the
   timer that renews the keys role's credentials in
   `/run/ftw-cloud-keys-aws`, and sets `FTW_CLOUD_KMS_KEY`,
   `FTW_CLOUD_OFFER_KEY` and `COMPOSE_PROFILES=agents` in
   `/etc/ftw-cloud/compose.env`.

6. **Deploy** as usual (`ftw-cloud-deploy sha256:<digest>`). Compose starts
   `ftwkeysd` beside `ftwcloudd`. Its log says `ftwkeysd listening` with the
   offer key's kid.

7. **Pin the offer key** in Core and the apps (srcfl/ftw `docs/agents.md`,
   "The grant offer"): until a build pins it, no offer opens. Take the kid and
   public half from `ftwkeysd` on the host, through SSM, not from the public
   `/.well-known/ftw-offer-key`:

   ```bash
   id=$(aws ssm send-command --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc \
     --document-name AWS-RunShellScript \
     --parameters 'commands=["cd /opt/ftw-cloud/deploy && docker compose --env-file /etc/ftw-cloud/compose.env exec -T ftwkeysd /usr/local/bin/ftwkeysd offerkey -offer-kms-key=alias/ftw-cloud-offer-key -aws-credentials=/run/secrets/aws/credentials.json"]' \
     --query Command.CommandId --output text)
   aws ssm get-command-invocation --region eu-north-1 --instance-id i-0ecac4cbc6b5f8adc \
     --command-id "$id" --query StandardOutputContent --output text
   ```

   It prints `kid …` and `pub …`. KMS gives the same public half to an
   admin, as a cross-check that needs no host:

   ```bash
   aws kms get-public-key --region eu-north-1 --key-id alias/ftw-cloud-offer-key \
     --query PublicKey --output text | python3 -c 'import base64,hashlib,sys
   p=base64.b64decode(sys.stdin.read())[-65:]; b=lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
   print("kid", b(hashlib.sha256(p).digest())[:16]); print("pub", b(p))'
   ```

To turn assistants off again, remove `COMPOSE_PROFILES=agents` and deploy.
Approved agents stay sealed in the volume and work again when it comes back,
unless their owners revoked them meanwhile.

## Development

```bash
go run -tags ftwclouddev ./cmd/ftwkeysd filekey -out dev-keys.key
go run -tags ftwclouddev ./cmd/ftwkeysd -socket /tmp/ftwkeys/keys.sock \
  -state /tmp/ftwkeys/state -file-key dev-keys.key
```

A development build seals keys with the file key and signs offers with a
local key in the state directory. Whoever reads the file and the state
directory has every agent key, so a production build refuses both: it needs
`-kms-key` and `-offer-kms-key`.
