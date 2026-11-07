# Demo: PkgGuard in five minutes

A scripted run-through that uses only real traffic. Nothing is mocked, and the dashboard fills up from the demo itself.

The story: **one Gateway rule, a live malware feed, and an honest account of what it can and cannot do.** The pacing below fits five minutes if the preflight is done beforehand.

Replace `pkgguard.example.com` with your admin hostname.

## Preflight (before the audience arrives)

Do this ten minutes ahead, not in front of people.

1. **The rule is on and in sync.**
   ```bash
   npm run gateway:rule -- status
   ```
   Expect `ENABLED` and `in sync with the desired configuration`.
2. **Enforcement is on.** The last `npm run deploy:filter` printed `enforcement: ON`. If you are unsure, redeploy it: it prints the mode every time.
3. **The test packages still exist.** Registries remove malware, so this can change between demos.
   ```bash
   npm view vfat-tools@0.0.1-security version                       # an npm malware package
   curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/zennittts/0.1.0/json   # expect 200
   ```
   If either is gone, find another entry the index flags as malware that is still downloadable, and use it throughout.
4. **The client device is enrolled, its Cloudflare One session is active, and its registry traffic is decrypted.** Without an identity, the rule does not match and nothing is filtered. Being in the rule's scope is not enough: if the user is still covered by your Do Not Inspect exemption, malware downloads silently and the dashboard stays empty. Check the TLS issuer, which must name Cloudflare, not the registry's own CA, for each host:
   ```bash
   for h in registry.npmjs.org pypi.org files.pythonhosted.org; do printf '%-24s ' $h; curl -sv -m 8 -o /dev/null https://$h/ 2>&1 | grep -E '^\*  issuer'; done
   ```
5. **Open three windows:** a terminal on the enrolled device, the dashboard at `https://pkgguard.example.com`, and the Chat space that receives alerts.
6. **Warm the dashboard with real traffic, but not with the package you will block live.** Run the clean installs from act 2 once, so the feed is not empty.

> **Alerts are limited to one per package, per user, per hour.** If you warm up by blocking `vfat-tools` and then block it again in the demo within the hour, the second block is recorded but sends **no Chat message**. Warm up with a different malware package, or block your live one for the first time on stage.

> **pip serves a cached package without touching the network**, so PkgGuard never sees it and the dashboard gets no new row. Use `--no-cache-dir` for every pip command in the demo. npm behaves the same for `npm install` of a package it has cached, so warm up with a package the audience will not reinstall, and expect no new row on a repeat.

Work in a scratch directory so a successful download leaves nothing behind: `cd "$(mktemp -d)"`.

## The script

### 1. The problem, and the one rule (0:00 – 0:45)

**Say:** Gateway can block a package by name, but OSV has hundreds of thousands of advisories and Gateway allows 500 policies. You cannot encode a live feed as policies.

**Show:** the Gateway dashboard with the single Forward rule, then PkgGuard's status cards: advisory counts per ecosystem and the last refresh.

**Say:** One rule sends package traffic to a Worker. The data lives in D1 and KV and refreshes on its own: nightly, and monthly in full.

### 2. Normal work is untouched (0:45 – 1:30)

```bash
npm pack left-pad@1.3.0
python3 -m pip download --no-cache-dir requests==2.25.0 --no-deps -d .
```

Both succeed. `requests==2.25.0` has a known vulnerability but is not malware.

**Show:** the dashboard feed. `left-pad` is **Allowed**. `requests` is **Flagged**, with its advisory.

**Say:** The policy is deliberate: block malware, log vulnerabilities. Blocking every CVE would break most real builds, and teams would switch the control off within a week.

### 3. Malware is stopped (1:30 – 2:45)

```bash
npm pack vfat-tools@0.0.1-security
ls
```

Expect `npm error code E403`, and an error line that says why, links the advisory, and carries a reference such as `PG-7Q2K4M`. `ls` shows nothing downloaded.

**Show:**
- the **Chat alert**: package, user, advisory, reference, and "blocked";
- the dashboard row, **Blocked**, then paste the reference into the **Reference** box to find it.

**Say:** The developer quotes the code, and security finds the event in one step. The alert names the person, one message per person per package per hour, so a repeated download does not flood the space.

### 4. What the developer sees in a browser (2:45 – 3:15) *optional*

Open `https://registry.npmjs.org/vfat-tools/-/vfat-tools-0.0.1-security.tgz` in a browser on the same device.

**Show:** the block page. It is a single self-contained page with no scripts or external requests, in light or dark mode, and the reference is selectable.

Skip this act if you are short on time; it adds the most polish and the least substance.

### 5. A false positive is a ten-second fix (3:15 – 4:00)

**Say:** Every control gets a false positive eventually. Here is what the fix looks like.

In the dashboard's **Overrides** panel, add an **Allow** for the blocked package (ecosystem `npm`, package `vfat-tools`, leave versions blank), then retry the install. It normally works within seconds. KV propagation can take up to a minute, so if the first retry is still blocked, carry on with the next act and come back to it.

```bash
npm pack vfat-tools@0.0.1-security      # downloads now
```

Remove the override afterwards, and show that the next attempt is blocked again.

**Say:** Allow beats block, and both beat OSV. Every change is audited and posts to Chat.

### 6. The kill switch, and the honest limits (4:00 – 5:00)

```bash
npm run gateway:rule -- disable
npm pack vfat-tools@0.0.1-security      # downloads normally now
npm run gateway:rule -- enable
```

**Say:** Turning it off takes seconds. A control that you cannot switch off is a control people are afraid to switch on.

Close with the limits, because they are the questions you will be asked:

- **pip users see only `403 Forbidden`.** Nothing in the response reaches pip's output. The detail is in the alert and the dashboard.
- **It only controls downloads that cross the network.** A package already in pip's or npm's local cache installs without being checked. A blocked package is never cached, so the gap is a package cached before it was flagged.
- **PyPI coverage is thinner than npm.** PyPI removes malware quickly and most never gets an advisory. It is supported, not equivalent.
- **Identity scoping.** A device with no active Cloudflare One session is not filtered.

## If something goes wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| Malware **downloads** instead of being blocked | Enforcement is off, the device has no identity, the rule is disabled, or the user is still on Do Not Inspect for the registry (the TLS issuer is not Cloudflare's) | `npm run gateway:rule -- status`; check the device's session; confirm the deploy printed `enforcement: ON` |
| No Chat alert on a block | Already alerted for that package and user in the last hour | Block a package you have not blocked recently |
| No new dashboard row for an install that worked | The client served it from its local cache | `pip --no-cache-dir`; for npm, use a package not installed before |
| The test package returns 404 | The registry removed it | Pick another flagged package that still exists |
| The override has no effect yet | KV propagation, normally seconds | Wait up to a minute |
| The dashboard says the session ended | The Access session expired | Reload and sign in again |

## After the demo

- Remove any demo overrides from the dashboard.
- Confirm the rule is **enabled**: `npm run gateway:rule -- status`.
- Detections stay in the dashboard. They are real events and cost nothing to keep.
