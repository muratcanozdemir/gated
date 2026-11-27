# Examples

Copy-pasteable policy data for gated. Each file is a complete JSON object
that is merged into the daemon's `data.json`; see the
[Waivers](https://github.com/muratcanozdemir/gated#waivers) section for what every field means.

| File | What it shows |
|------|---------------|
| [`waivers/one-package.json`](waivers/one-package.json) | One vulnerability waived for one npm package |
| [`waivers/several-ecosystems.json`](waivers/several-ecosystems.json) | Several waivers: PyPI, Maven (`groupId:artifactId`), and one for every package |
| [`waivers/dependency.json`](waivers/dependency.json) | A vulnerability in a dependency (gopls and golang.org/x/net) |

## Adding a waiver

Before you start, edit the example: put your own vulnerability ID, packages,
`reason` and an `expires` date in the future. A waiver whose date has passed
is ignored.

### 1. Merge it into `data.json`

User service (`~/.config/gated/policy`):

```bash
POLICY=~/.config/gated/policy
curl -fsSLO https://raw.githubusercontent.com/muratcanozdemir/gated/main/docs/examples/waivers/one-package.json
# edit one-package.json now
cp "$POLICY/data.json" "$POLICY/data.json.bak"
jq -s '.[0] * .[1]' "$POLICY/data.json.bak" one-package.json > "$POLICY/data.json"
```

System service (`/etc/gated/policy`):

```bash
POLICY=/etc/gated/policy
curl -fsSLO https://raw.githubusercontent.com/muratcanozdemir/gated/main/docs/examples/waivers/one-package.json
# edit one-package.json now
sudo cp "$POLICY/data.json" "$POLICY/data.json.bak"
jq -s '.[0] * .[1]' "$POLICY/data.json.bak" one-package.json | sudo tee "$POLICY/data.json" > /dev/null
```

`jq`'s `*` keeps the waivers you already have and adds the new ones. If a
vulnerability ID is already waived, its fields are replaced by the example's,
and `packages` is replaced, not extended.

### 2. Check it

```bash
gated -validate -config ~/.config/gated/config.yaml    # system: /etc/gated/config.yaml
```

It prints `config and policies OK` even if a waiver is broken. Look above
that line for `WARN` lines saying `expired on` or `has no valid "expires"
date`: those waivers do nothing.

### 3. Reload the daemon

gated reads `data.json` only at startup and on reload. **A waiver does
nothing until you reload the daemon.**

```bash
# User service
systemctl --user reload gated
journalctl --user -u gated -n 5 -o cat

# System service (gated.service or gated-unprivileged.service)
sudo systemctl reload gated
sudo journalctl -u gated -n 5 -o cat

# No systemd
kill -HUP "$(pidof gated)"
```

The log must say `policy reload complete`. If it says `policy reload
validation failed, keeping old policies`, the daemon is still running on the
old policies, without your waiver: fix the error it names, or restore
`data.json.bak`, and reload again.

The reload also empties the verdict cache, so a package that was denied
before is scanned again on the next install.

### 4. Retry the install

Run the install that was denied. When the fix ships, delete the waiver from
`data.json` and reload again.
