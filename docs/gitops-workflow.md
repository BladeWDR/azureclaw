# GitOps Workflow for Azureclaw

With `bootc`, the container image is the immutable source of truth for your operating system, base packages, firewall rules, and default network policies. Managing your router via GitOps eliminates configuration drift and ensures reproducible rollouts across your infrastructure.

---

## The Workflow Cycle

```
  ┌────────────────────────────────────────────────────────┐
  │ 1. Git Repository                                      │
  │    (Containerfile, nftables.conf, dnsmasq.conf, etc.)  │
  └───────────────────────────┬────────────────────────────┘
                              │ git push
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │ 2. CI/CD Runner (GitHub Actions / GitLab CI)           │
  │    Builds container image with Buildx                  │
  └───────────────────────────┬────────────────────────────┘
                              │ docker push
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │ 3. OCI Container Registry                              │
  │    (ghcr.io/youruser/azureclaw:latest)                 │
  └───────────────────────────┬────────────────────────────┘
                              │ bootc upgrade
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │ 4. Azureclaw Router VM                                 │
  │    - Daily timer checks registry for new digest        │
  │    - Atomic OSTree commit downloaded & staged          │
  │    - Clean reboot during 04:00 AM maintenance window   │
  └────────────────────────────────────────────────────────┘
```

---

## 1. Setting Up Automated Builds with GitHub Actions

Create `.github/workflows/build-and-push.yml` in your repository:

```yaml
name: Build and Publish Router Image

on:
  push:
    branches:
      - main
    paths-ignore:
      - 'docs/**'
      - 'README.md'
      - 'ansible/**'

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write

    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Log in to the Container registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build and push container image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./Containerfile
          push: true
          tags: |
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

---

## 2. Switching Router to Track Your Registry Image

When first booting from a generic disk image, switch the target container image reference on the router to your personal registry:

```bash
# Switch deployment source to your personal repository
bootc switch ghcr.io/<your-username>/azureclaw:latest
systemctl reboot
```

Once switched, the router tracks your registry directly.

---

## 3. Maintenance Windows & Automatic Updates

The router includes a dedicated systemd timer:
- `/usr/lib/systemd/system/bootc-auto-update.timer`
- `/usr/lib/systemd/system/bootc-auto-update.service`

### Customizing the Maintenance Schedule:
If you want updates to run at a different time (e.g. 03:00 AM Sundays):
```bash
# Override systemd timer via drop-in
mkdir -p /etc/systemd/system/bootc-auto-update.timer.d/
cat << 'EOF' > /etc/systemd/system/bootc-auto-update.timer.d/override.conf
[Timer]
OnCalendar=
OnCalendar=Sun *-*-* 03:30:00
EOF

systemctl daemon-reload
systemctl restart bootc-auto-update.timer
```

---

## 4. Rollback and Recovery via Git

If a change introduces an unexpected bug:
1. **Instant local rollback**:
   ```bash
   bootc rollback
   systemctl reboot
   ```
2. **GitOps-driven rollback**:
   Revert the faulty commit on the `main` branch:
   ```bash
   git revert HEAD
   git push origin main
   ```
   CI will build the reverted image and push it to the registry; the router will update to it during the next cycle.
