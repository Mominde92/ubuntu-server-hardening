# Ubuntu Server Hardening

[![CI](https://github.com/Mominde92/ubuntu-server-hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/Mominde92/ubuntu-server-hardening/actions/workflows/ci.yml)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04-E95420?logo=ubuntu&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-ShellCheck_clean-4EAA25?logo=gnubash&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)

One script that applies the security baseline I run on every new Ubuntu web server before an application goes live.
It is **tested on a real Ubuntu 24.04 machine on every push**: CI hardens a GitHub runner, runs the script a second time,
then proves that key login works, password login is refused and the firewall and fail2ban are active.

## What it does

| Area | Change |
|---|---|
| Admin user | Creates a sudo user with your SSH public key (reuses it if it exists). |
| SSH | Keys only, no root login, no passwords, `MaxAuthTries 3`, shorter login grace time. Written to `sshd_config.d/00-hardening.conf` so it wins over cloud-init's `50-cloud-init.conf`. |
| Firewall | `ufw`: deny incoming, allow outgoing, open only SSH, 80 and 443. |
| Updates | Unattended security upgrades every day. |
| Brute force | `fail2ban` jail for SSH (5 failures in 10 minutes = 1 hour ban). |

## Safety built in

- **Lock-out guard**: password login is not disabled unless the user's `authorized_keys` contains a key.
- **Config validation**: the new SSH config is checked with `sshd -t`; if it is invalid it is removed and SSH is not restarted.
- **Sudo still works**: if the user has no password, a validated passwordless sudo rule is added so you are not left without root access.
- **Idempotent**: running it again does not duplicate keys or rules.
- **Dry run**: `--dry-run` prints every change without touching the server.
- Handles Ubuntu 24.04 SSH socket activation when the port changes.

## Usage

```bash
curl -fsSLO https://raw.githubusercontent.com/Mominde92/ubuntu-server-hardening/main/harden.sh
less harden.sh                      # always read a script before running it as root
chmod +x harden.sh

sudo ./harden.sh --user deploy --pubkey-file ~/.ssh/id_ed25519.pub --dry-run
sudo ./harden.sh --user deploy --pubkey-file ~/.ssh/id_ed25519.pub
```

> Keep your current SSH session open and test `ssh deploy@<server>` from a **new** terminal before you log out.

### Options

```
--user NAME          Admin user to create (or reuse). Root login is disabled afterwards.
--pubkey KEY         SSH public key allowed to log in as NAME.
--pubkey-file FILE   Read the public key from FILE.
--ssh-port PORT      SSH port to allow and listen on (default 22).
--no-web             Do not open ports 80 and 443.
--dry-run            Print the changes without applying them.
```

## What it does not do

Hardening the host is the first layer. Your application still needs HTTPS (for example `certbot --nginx`),
a database that listens only on `127.0.0.1`, secrets outside the web root, security headers, monitoring and tested backups.
The full checklist with explanations: [Ubuntu server hardening checklist for web applications](https://moumen-dev.com/blog/ubuntu-server-hardening-checklist/).

## Author

**Moamen Derine**, Senior Full Stack Developer & DevOps Engineer in Dubai.
[moumen-dev.com](https://moumen-dev.com) · [LinkedIn](https://www.linkedin.com/in/momin-derine/)

## License

[MIT](LICENSE)
