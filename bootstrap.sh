#!/bin/bash
# bootstrap.sh - prepare an Arch Linux host and generate Ansible variable files
# for ansible_arch.

set -euo pipefail

REPO_DIR="${REPO_DIR:-$HOME/ansible_arch}"
CUSTOM_YAML="$REPO_DIR/custom.yml"
SECRET_YAML="$REPO_DIR/secret.yml"

# Detect OS
if ! grep -qs "arch" /etc/os-release; then
    echo "This installer only supports Arch Linux."
    exit 1
fi

# Determine sudo usage
SUDO=''
if [[ $EUID -ne 0 ]]; then
    SUDO='sudo -E'
fi

# Install required system packages
$SUDO pacman -Syu --noconfirm
$SUDO pacman -S --needed --noconfirm curl git ansible-core ansible

# Ensure the repo/config directory exists
mkdir -p "$REPO_DIR"

# Start with a fresh custom.yml
: > "$CUSTOM_YAML"

clear
echo "Welcome to ansible_arch!"
echo
echo "This script is interactive."
echo "If you prefer to fill in custom.yml manually, press [Ctrl+C] to quit."
echo

# Username
read -rp "Desired UNIX username: " username
until [[ "$username" =~ ^[a-z0-9]+$ ]]; do
    echo "Invalid username. Use only lowercase letters and numbers."
    read -rp "Desired UNIX username: " username
done

echo "username: \"${username}\"" >> "$CUSTOM_YAML"
echo "enable_username_creation: true" >> "$CUSTOM_YAML"
echo "enable_passwordless_sudo: true" >> "$CUSTOM_YAML"

# Password
while true; do
    read -rsp "Password: " user_password
    echo
    if [[ "${#user_password}" -lt 60 ]]; then
        break
    fi
    echo "Password too long. OpenSSH does not support passwords longer than 72 characters."
done

read -rsp "Repeat password: " user_password2
echo
until [[ "$user_password" == "$user_password2" ]]; do
    echo "Passwords do not match."
    read -rsp "Password: " user_password
    echo
    read -rsp "Repeat password: " user_password2
    echo
done

# Domain name
read -rp "Domain name (e.g. example.duckdns.org): " root_host
echo "root_host: \"${root_host}\"" >> "$CUSTOM_YAML"

# Optional e-mail setup
read -rp "Set up e-mail for Authelia notifications? [y/N]: " email_setup
until [[ "$email_setup" =~ ^[yYnN]*$ ]]; do
    echo "$email_setup: invalid selection."
    read -rp "Set up e-mail for Authelia notifications? [y/N]: " email_setup
done

if [[ "$email_setup" =~ ^[yY]$ ]]; then
    read -rp "SMTP server: " email_smtp_host
    read -rp "SMTP port [465]: " email_smtp_port
    email_smtp_port="${email_smtp_port:-465}"
    read -rp "SMTP login: " email_login
    read -rsp "SMTP password: " email_password
    echo
    read -rp "'From' e-mail [${email_login}]: " email
    email="${email:-$email_login}"
    read -rp "'To' e-mail [${email_login}]: " email_recipient
    email_recipient="${email_recipient:-$email_login}"

    {
        echo "email_smtp_host: \"${email_smtp_host}\""
        echo "email_smtp_port: ${email_smtp_port}"
        echo "email_login: \"${email_login}\""
        echo "email: \"${email}\""
        echo "email_recipient: \"${email_recipient}\""
    } >> "$CUSTOM_YAML"
fi

# Generate secrets
jwt_secret=$(openssl rand -hex 32)
session_secret=$(openssl rand -hex 32)
storage_encryption_key=$(openssl rand -hex 32)

# Write secret.yml with restrictive permissions
(
    umask 077
    : > "$SECRET_YAML"
    echo "user_password: \"${user_password}\"" >> "$SECRET_YAML"
    if [[ "${email_password:-}" != "" ]]; then
        echo "email_password: \"${email_password}\"" >> "$SECRET_YAML"
    fi
    echo "jwt_secret: ${jwt_secret}" >> "$SECRET_YAML"
    echo "session_secret: ${session_secret}" >> "$SECRET_YAML"
    echo "storage_encryption_key: ${storage_encryption_key}" >> "$SECRET_YAML"
)

chmod 600 "$SECRET_YAML"

echo
echo "Encrypting secret.yml with ansible-vault..."
ansible-vault encrypt "$SECRET_YAML"

echo
echo "Bootstrap complete."
echo
echo "Variables written to:"
echo "  $CUSTOM_YAML"
echo "  $SECRET_YAML"
echo
read -rp "Run the playbook now? [y/N]: " launch_playbook
until [[ "$launch_playbook" =~ ^[yYnN]*$ ]]; do
    echo "$launch_playbook: invalid selection."
    read -rp "Run the playbook now? [y/N]: " launch_playbook
done

if [[ "$launch_playbook" =~ ^[yY]$ ]]; then
    cd "$REPO_DIR"
    if [[ $EUID -ne 0 ]]; then
        ansible-playbook -K run.yml
    else
        ansible-playbook run.yml
    fi
else
    echo "You can run the playbook later with:"
    echo "  cd ${REPO_DIR} && ansible-playbook run.yml"
fi
