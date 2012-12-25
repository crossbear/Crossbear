#!/bin/bash
for ip in $(nslookup $1 | grep Address | grep -v "Address:.*53" | sed -s 's/Address:\ //g'); do
  dig -t TXT $ip.cbssh.net.in.tum.de
done
