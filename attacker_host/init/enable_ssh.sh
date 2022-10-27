#!/bin/sh
rm -f /etc/service/sshd/down
/etc/my_init.d/00_regen_ssh_host_keys.sh
echo "PasswordAuthentication yes" >> /etc/ssh/ssh_config