# AWS controls for the Probe stage

The local demo covers the worker sandbox (`nonet`, the probes, the self-test).
This file covers the other half of the article: the Probe Lambda, which **does**
need the network because ffprobe reads the upload from S3 over HTTPS, so `nonet`
cannot be used there. These are AWS configuration, not code, so nothing in this
repo can exercise them and there is no Terraform here. Wire the account IDs,
region and bucket name to your own before use.

I run the gate Lambda and all five controls below in production, the probe's VPC
of its own included.

## How the probe is called

Step Functions calls a small **gate** Lambda, outside the cage. The gate signs a
fresh presigned GET for the one upload (its key and `versionId`, 10-minute
expiry) and invokes the caged Probe Lambda synchronously with it. The gate makes
that call itself so the URL never reaches Step Functions, whose execution history
records every state's input and output. The Probe runs ffprobe and returns its
verdict or an error name, which the gate passes through:

- `Probe.Rejected`: a bad or hostile file. No retrier matches it, and the user is
  told.
- `Probe.Transient`: the fetch failed or ran past its deadline (see below). Step Functions
  retries it, and every retry goes back through the gate for a fresh URL.
- `Probe.Fault`: the caged Probe crashed, timed out or ran out of memory. A
  hijacked ffprobe can cause each of these, so there is no retry, no user notice,
  and a security page (control 5).

Accepted jobs reach SQS from Step Functions, with `.waitForTaskToken`. The Probe
never touches SQS.

## 1. A VPC of its own, S3 gateway endpoint only

The Probe runs in private subnets of its own VPC, with **no NAT gateway and no
internet gateway**. The route table has two entries: the local VPC CIDR, and a
route to an S3 **gateway** VPC endpoint. The endpoint policy narrows it to the
one bucket and the one action, `s3:GetObjectVersion`, because a GET that names a
`versionId` needs that action instead of `s3:GetObject`:

See [`s3-gateway-endpoint-policy.json`](s3-gateway-endpoint-policy.json).

A gateway endpoint has no network interface or IP in your subnet. The route
sends traffic for S3's public prefix-list ranges to the endpoint, and it stays on
the AWS network. Those IPs serve every bucket in the Region, an attacker's
included, so the endpoint policy does the restricting. A gateway endpoint is also
free, unlike an interface endpoint.

The VPC is the Probe's alone because of control 3: DNS Firewall rule groups
attach to a whole VPC, and in a VPC shared with the workers the block rule would
stop their DNS for SQS, ECR and logs too.

## 2. Security group egress to the S3 prefix list only

A security group with `0.0.0.0/0` egress can reach every interface endpoint in
its VPC (STS, SQS, SSM, Secrets Manager on private RFC1918 IPs). The Probe's VPC
has none, so this is a second check, in case one is ever added. Lock egress to the
AWS-managed S3 prefix list on 443:

```
Egress:
  - Destination: pl-xxxxxxxx   # com.amazonaws.<region>.s3 managed prefix list
    Protocol: tcp
    Port: 443
  # no other egress rules -> implicit deny
```

This also drops direct DoH to `8.8.8.8:443` or `1.1.1.1:443`, at L4.

## 3. Route 53 Resolver DNS Firewall allow-list

Security groups do not filter DNS to the VPC resolver (`AmazonProvidedDNS`, the
VPC base IP + 2). So `dig secret.attacker.com` still recurses out and leaks
through the attacker's name server. Close it with a DNS Firewall rule group on the
Probe VPC: an ALLOW rule for the exact bucket host the presigned URL uses, and a
lower-priority BLOCK rule on `*`.

Allow-list, one entry, because the gate always signs the regional
virtual-hosted form:

```
<ingest-bucket>.s3.<region>.amazonaws.com
```

That name CNAMEs to an AWS-internal host such as `s3-r-w.<region>.amazonaws.com`,
which is undocumented and can change. By default the firewall re-checks every name
in the redirection chain (`INSPECT_REDIRECTION_DOMAIN`), so the probe's own lookup
would be blocked. Set the ALLOW rule to `TRUST_REDIRECTION_DOMAIN`, so only the
first name is inspected. That is safe because S3, not the uploader, answers for an
S3 name's chain.

Sketch with the AWS CLI (fill in the domain-list and rule-group IDs):

```bash
aws route53resolver create-firewall-rule \
  --firewall-rule-group-id  rslvr-frg-EXAMPLE \
  --firewall-domain-list-id rslvr-fdl-INGEST \
  --priority 100 \
  --action ALLOW \
  --firewall-domain-redirection-action TRUST_REDIRECTION_DOMAIN \
  --name allow-ingest-bucket

aws route53resolver create-firewall-rule \
  --firewall-rule-group-id  rslvr-frg-EXAMPLE \
  --firewall-domain-list-id rslvr-fdl-ALL \
  --priority 999 \
  --action BLOCK \
  --block-response NODATA \
  --name block-everything-else
```

Keep the VPC's DNS Firewall fail mode closed (the default), alarm on any BLOCK
from this VPC, and create the rule group in each Region, the DR Region included.
It costs $0.60 per million queries, about $2 a month at 14K uploads a day.

Together: no routable egress except to S3 (controls 1 and 2), and no DNS
resolution except for the bucket's own name (control 3). Neither direct IP egress
nor recursive DNS tunneling reaches the public internet.

## 4. No keys worth stealing

Lambda puts the role's keys in environment variables, and ffprobe runs as a child
under the same user. A role's credentials exist for its own code to use, so
anything running under that role can reach them, and hiding them is not a control
to bet on: an empty `cmd.Env` blanks only the child's own environment, a same-user
child still reads the parent's `/proc/<pid>/environ` (unsetting the keys in the
parent doesn't change that file either, tested), a copy also lives in the memory
of Lambda's init process, and extensions share the function's keys.

So the caged Probe's role holds **no S3 permission at all**. The gate signs. What
the role must keep is small. A VPC function's role holds the network-interface
actions Lambda uses, and AWS notes they are "implicitly granted to your function's
code", so add AWS's documented Deny on those actions, conditioned on
`lambda:SourceFunctionArn`, which takes them away from the code but not from Lambda.
Scope log writes to the function's own log group. A stolen key then opens nothing
worth having.

The handler starts ffprobe with an empty environment and runs no extensions. It
does not mark itself non-dumpable: a build-time check (control 5) found the Lambda
sandbox refuses `PR_SET_DUMPABLE`, so unlike the worker the probe cannot hide its
memory or `/proc` that way. That is acceptable precisely because the role opens
nothing: the only thing worth reading, the role's keys, is worth nothing.

The URL itself is live for 10 minutes, so keep it out of Step Functions history,
error causes and logs. Ask ffprobe for named `format` fields, because it prints the
URL as `filename`, and strip the URL from ffprobe's stderr before it goes into an
error cause or a log. A
build-time check in the Probe's sandbox tries every `/proc/*/environ`,
`/proc/*/mem` and `process_vm_readv` for the role's secret key and records what a
child can read.

## 5. One video per sandbox

Lambda reuses an execution environment across invocations, and a process left
running is frozen with it and resumes in the next invocation. There it could read
the next upload's presigned URL from ffprobe's command line. So before each
invocation returns, the handler kills and reaps the processes ffprobe left that it
can see. It attempts `prctl(PR_SET_CHILD_SUBREAPER)` so even a `setsid` orphan would
stay its child to reap, but the Lambda sandbox refuses that prctl (a build-time
check, below), so such an orphan reparents to the runtime's init (PID 1; the handler
is PID 2) and the `ShouldExit` reset below is what covers it. ffprobe never forks, so
a leftover means a hijack. The file is `Probe.Rejected` and a security alarm fires.
This also catches a hijack that exits 0.

A bare process exit is the wrong way to reset the environment. Step Functions
sees it as `Lambda.Unknown`, not `Probe.Rejected`, so a hostile file would skip the
"rejected, user notified" path, and AWS notes that the reset "does not clear the
`/tmp` directory content". The one exit the handler does make is for a leftover it
cannot reap: if a leftover survives the 5 s kill loop, it returns `Probe.Rejected`
with `ShouldExit`, which `aws-lambda-go` posts to Lambda before it exits, so the
verdict stands and the next invocation gets a fresh environment.

A hijacked ffprobe runs as the handler's user, so it can also kill or freeze the
handler itself, which skips all of the above. That ends as a crash or a timeout,
which the gate turns into `Probe.Fault`: no retry, no user notice, and a security
page. AWS doesn't document whether a reset kills a process the runtime started, so
that is a build-time test.

A build-time check in a real Lambda found its sandbox refuses all three:
`PR_SET_CHILD_SUBREAPER`, `PR_SET_DUMPABLE` and seccomp-filter installation
(`PR_SET_NO_NEW_PRIVS` itself is refused), and that `/proc` has no `hidepid`. So:

- The subreaper is refused, so the handler cannot reap a `setsid` orphan; such an
  orphan reparents to the runtime init. `/proc` has no `hidepid` (below), so the
  handler's scan after each call still sees any leftover, detached or non-dumpable.
  An honest file leaves none and keeps the warm environment. Any leftover means a
  hijack: the file is `Probe.Rejected`, and because an orphan survives the reap the
  handler returns `ShouldExit` to reset the environment and clear it. That reset is
  the real leftover defense for an orphan, since the subreaper that would reap it is
  refused.
- A seccomp filter does not install, so `nonet` cannot be put in front of ffprobe
  in Lambda. The probe does not need it there: ffprobe keeps the network on purpose
  (it reads S3), and the cage, not a filter, is what bounds it.
- `/proc` has no `hidepid`, so the scan above is reliable. The handler reads its
  `/proc` mount options at init and, if a future Lambda ever set `hidepid` (under
  which a non-dumpable leftover would vanish from the scan), fails closed by
  resetting after every file instead.

## Failed fetch or bad file

ffprobe exits 1 for a corrupt file and for a failed fetch alike (measured on
9.0.2: connection refused, DNS failure, HTTP 403, HTTP 5xx and invalid data all
exit 1). If the handler mapped every non-zero exit to `Probe.Rejected`, an S3
503, an expired URL or a DNS Firewall mistake would reject good uploads, with a
user notice and no retry. The handler sorts by ffprobe's stderr instead: a
network, DNS, TLS, HTTP 5xx or 403 line is `Probe.Transient`, and everything else
is `Probe.Rejected`. A CI test pins each of those lines against the pinned
FFmpeg build. Each ffprobe call also gets a deadline well under the function
timeout, so a slow fetch ends inside the handler as `Probe.Transient`, and the
gate's own throttled invoke is `Probe.Transient` too. A file that keeps ffprobe
reading until the deadline ends as `Probe.Transient` on purpose, so a slow S3 read
never rejects an honest upload.
