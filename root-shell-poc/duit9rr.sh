#!/bin/sh

tftp -g 192.168.1.2 -r dropbear -l /tmp/dropbear
tftp -g 192.168.1.2 -r hostkey -l /tmp/hostkey
tftp -g 192.168.1.2 -r rsa.pub -l /tmp/authorized_keys
iptables -I INPUT -p tcp --dport 2222 -j ACCEPT
chmod 777 /tmp/dropbear
chmod 600 /tmp/authorized_keys
if ! /tmp/dropbear -r /tmp/hostkey -p 2222 > /tmp/log 2>&1; then
  ls -l /tmp >> /tmp/log
  tftp -p 192.168.1.2 -l /tmp/log -r /tmp/dropbear.log
fi
