# ansible_arch

Ansible automation for an Arch Linux VPS running a WireGuard VPN protected by Authelia and exposed through BunkerWeb.

## Requirements

- Arch Linux target host
- Ansible 2.14+
- `community.general` and `community.docker` collections

Install dependencies:

```bash
ansible-galaxy collection install -r requirements.yml
```

## Quick start

1. Copy the example variables file and edit it for your domain and user:

   ```bash
   cp custom.yml.example custom.yml
   ```

2. Create an encrypted vault file with your secrets:

   ```bash
   ansible-vault create secret.yml
   ```

   At minimum `secret.yml` should contain:

   ```yaml
   user_password: "your-strong-password"
   jwt_secret: "<generate with openssl rand -hex 32>"
   session_secret: "<generate with openssl rand -hex 32>"
   storage_encryption_key: "<generate with openssl rand -hex 32>"
   ```

3. Run the playbook:

   ```bash
   ansible-playbook run.yml
   ```

## Bootstrap script

`bootstrap.sh` is an interactive helper that installs Ansible on Arch Linux and creates `custom.yml` and `secret.yml`. It is optional; you can create the files manually.

## Major dependency versions

| Service    | Image tag                        | Notes                                      |
|------------|----------------------------------|--------------------------------------------|
| WireGuard  | `ghcr.io/wg-easy/wg-easy:14`     | Migrated from unmaintained `weejewel/wg-easy:7`. Review the [wg-easy migration guide](https://wg-easy.github.io/wg-easy/latest/advanced/migrate/) before upgrading existing volumes. |
| Authelia   | `authelia/authelia:4.39`         | Pinned to the 4.x major line.              |
| BunkerWeb  | `bunkerity/bunkerweb:1.6`        | Pinned to the 1.6 major line.              |
| Redis      | `redis:alpine`                   |                                            |

## Role tags

Run only part of the playbook with `--tags`:

- `system`
- `docker`
- `ufw`
- `fail2ban`
- `wireguard`
- `authelia`
- `bunkerweb`

## Maintenance notes

- Package upgrades are **not** run automatically. Set `upgrade_packages: yes` in `custom.yml` to perform a full pacman upgrade.
- Always read upstream release notes before bumping major image tags.
