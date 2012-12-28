#!/bin/bash
for ip in $(dig +short $1); do
  dig -t TXT $ip.cbssh.net.in.tum.de
done
