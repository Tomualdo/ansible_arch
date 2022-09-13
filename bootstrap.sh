#!/bin/bash -uxe
# see the Bash: 4.3.1 The Set Builtin
# A bash script that prepares the OS
# before running the Ansible playbook

# Discard stdin. Needed when running from an one-liner which includes a newline
#read -N 999999 -t 0.001

# Quit on error
set -e

# Detect OS
if grep -qs "arch" /etc/os-release; then
	  os="arch"
	    os_version=$(grep 'BUILD_ID' /etc/os-release | cut -d '=' -f 2)
    else
	      echo "This installer seems to be running on an unsupported distribution."
	        echo "Supported distros are ..."
		  exit
fi

check_root() {
# Check if the user is root or not
if [[ $EUID -ne 0 ]]; then
#  if [[ ! -z "$1" ]]; then
#    SUDO='sudo -E -H'
#  else
    SUDO='sudo -E'
#  fi
else
  SUDO=''
fi
}

check_root

$SUDO pacman -Syu
$SUDO pacman -Suy --needed curl git ansible-core ansible


#########
touch $HOME/ansible_auto_vpn/custom.yml

clear
echo "Welcome to ansible-easy-vpn!"
echo
echo "This script is interactive"
echo "If you prefer to fill in the custom.yml file manually,"
echo "press [Ctrl+C] to quit this script"
echo
echo "Enter your desired UNIX username"
read -p "Username: " username
until [[ "$username" =~ ^[a-z0-9]*$ ]]; do
  echo "Invalid username"
  echo "Make sure the username only contains lowercase letters and numbers"
  read -p "Username: " username
done

echo "username: \"${username}\"" >> $HOME/ansible_auto_vpn/custom.yml

echo
echo "Enter your user password"
echo "This password will be used for Authelia login, administrative access and SSH login"
read -s -p "Password: " user_password
until [[ "${#user_password}" -lt 60 ]]; do
  echo
  echo "The password is too long"
  echo "OpenSSH does not support passwords longer than 72 characters"
  read -s -p "Password: " user_password
done
echo
read -s -p "Repeat password: " user_password2
echo
until [[ "$user_password" == "$user_password2" ]]; do
  echo
  echo "The passwords don't match"
  read -s -p "Password: " user_password
  echo
  read -s -p "Repeat password: " user_password2
done


echo
echo
echo "Enter your domain name"
echo "The domain name should already resolve to the IP address of your server"
echo "Make sure that 'wg' and 'auth' subdomains also point to that IP (not necessary with DuckDNS)"
echo
read -p "Domain name: " root_host
#until [[ "$root_host" =~ ^[a-z0-9\.\-]*$ ]]; do
#  echo "Invalid domain name"
#  read -p "Domain name: " root_host
#done
#
#public_ip=$(curl -s ipinfo.io/ip)
#domain_ip=$(dig +short @1.1.1.1 ${root_host})
#
#until [[ $domain_ip =~ $public_ip ]]; do
#  echo
#  echo "The domain $root_host does not resolve to the public IP of this server ($public_ip)"
#  echo
#  root_host_prev=$root_host
#  read -p "Domain name [$root_host_prev]: " root_host
#  if [ -z ${root_host} ]; then
#    root_host=$root_host_prev
#  fi
#  public_ip=$(curl -s ipinfo.io/ip)
#  domain_ip=$(dig +short @1.1.1.1 ${root_host})
#  echo
#done

#echo
#echo "Running certbot in dry-run mode to test the validity of the domain..."
#$SUDO certbot certonly --non-interactive --break-my-certs --force-renewal --agree-tos --email root@localhost.com --standalone --staging -d $root_host -d wg.$root_host -d auth.$root_host || exit
#echo "OK"

echo "root_host: \"${root_host}\"" >> $HOME/ansible_auto_vpn/custom.yml


#if [[ ! $aws =~ true ]]; then
#  echo
#  echo "Would you like to use an existing SSH key?"
#  echo "Press 'n' if you want to generate a new SSH key pair"
#  echo
#  read -p "Use existing SSH key? [y/N]: " new_ssh_key_pair
#  until [[ "$new_ssh_key_pair" =~ ^[yYnN]*$ ]]; do
#          echo "$new_ssh_key_pair: invalid selection."
#          read -p "[y/N]: " new_ssh_key_pair
#  done
#  echo "enable_ssh_keygen: true" >> $HOME/ansible_auto_vpn/custom.yml
#
#  if [[ "$new_ssh_key_pair" =~ ^[yY]$ ]]; then
#    echo
#    read -p "Please enter your SSH public key: " ssh_key_pair
#
#    echo "ssh_public_key: \"${ssh_key_pair}\"" >> $HOME/ansible_auto_vpn/custom.yml
#  fi
#else
#  echo
#  read -p "Are you running this script on an AWS EC2 instance? [y/N]: " aws_ec2
#  until [[ "$aws_ec2" =~ ^[yYnN]*$ ]]; do
#          echo "$aws_ec2: invalid selection."
#          read -p "[y/N]: " aws_ec2
#  done
#  if [[ "$aws_ec2" =~ ^[yY]$ ]]; then
#    export AWS_EC2=true
#  echo
#  echo "Please use the SSH keys that you specified in the AWS Management Console to log in to the server."
#  echo "Also, make sure that your Security Group allows inbound connections on 51820/udp, 80/tcp and 443/tcp."
#  echo
#  fi
#fi

echo
echo "Would you like to set up the e-mail functionality?"
echo "It will be used to confirm the 2FA setup and restore the password in case you forget it"
echo
echo "This is optional"
echo
read -p "Set up e-mail? [y/N]: " email_setup
until [[ "$email_setup" =~ ^[yYnN]*$ ]]; do
				echo "$email_setup: invalid selection."
				read -p "[y/N]: " email_setup
done

if [[ "$email_setup" =~ ^[yY]$ ]]; then
  echo
  read -p "SMTP server: " email_smtp_host
  until [[ "$email_smtp_host" =~ ^[a-z0-9\.]*$ ]]; do
    echo "Invalid SMTP server"
    read -p "SMTP server: " email_smtp_host
  done
  echo
  read -p "SMTP port [465]: " email_smtp_port
  if [ -z ${email_smtp_port} ]; then
    email_smtp_port="465"
  fi
  echo
  read -p "SMTP login: " email_login
  echo
  read -s -p "SMTP password: " email_password
  until [[ ! -z "$email_password" ]]; do
    echo "The password is empty"
    read -s -p "SMTP password: " email_password
  done
  echo
  echo
  read -p "'From' e-mail [${email_login}]: " email
  if [ ! -z ${email} ]; then
    echo "email: \"${email}\"" >> $HOME/ansible_auto_vpn/custom.yml
  fi

  read -p "'To' e-mail [${email_login}]: " email_recipient
  if [ ! -z ${email_recipient} ]; then
    echo "email_recipient: \"${email_recipient}\"" >> $HOME/ansible_auto_vpn/custom.yml
  fi



  echo "email_smtp_host: \"${email_smtp_host}\"" >> $HOME/ansible_auto_vpn/custom.yml
  echo "email_smtp_port: \"${email_smtp_port}\"" >> $HOME/ansible_auto_vpn/custom.yml
  echo "email_login: \"${email_login}\"" >> $HOME/ansible_auto_vpn/custom.yml
fi


# Set secure permissions for the Vault file
touch $HOME/ansible_auto_vpn/secret.yml
chmod 600 $HOME/ansible_auto_vpn/secret.yml

if [ -z ${email_password+x} ]; then
  echo
else 
  echo "email_password: \"${email_password}\"" >> $HOME/ansible_auto_vpn/secret.yml
fi

echo "user_password: \"${user_password}\"" >> $HOME/ansible_auto_vpn/secret.yml

jwt_secret=$(openssl rand -hex 23)
session_secret=$(openssl rand -hex 23)
storage_encryption_key=$(openssl rand -hex 23)

echo "jwt_secret: ${jwt_secret}" >> $HOME/ansible_auto_vpn/secret.yml
echo "session_secret: ${session_secret}" >> $HOME/ansible_auto_vpn/secret.yml
echo "storage_encryption_key: ${storage_encryption_key}" >> $HOME/ansible_auto_vpn/secret.yml

echo
echo "Encrypting the variables"
ansible-vault encrypt $HOME/ansible_auto_vpn/secret.yml

echo
echo "Success!"
read -p "Would you like to run the playbook now? [y/N]: " launch_playbook
until [[ "$launch_playbook" =~ ^[yYnN]*$ ]]; do
				echo "$launch_playbook: invalid selection."
				read -p "[y/N]: " launch_playbook
done

#if [[ "$launch_playbook" =~ ^[yY]$ ]]; then
#  if [[ $EUID -ne 0 ]]; then
#    echo
#    echo "Please enter your current sudo password now"
#    cd $HOME/ansible_auto_vpn && ansible-playbook -K run.yml
#  else
#    cd $HOME/ansible_auto_vpn && ansible-playbook run.yml
#  fi
#else
#  echo "You can run the playbook by executing the following command"
#  echo "cd ${HOME}/ansible_auto_vpn && ansible-playbook run.yml"
#  exit
#fi
#
