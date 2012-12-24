#!/bin/bash
ip=$(echo $(host -t a $1) | sed 's/.*address\ //g')
dig -t TXT $ip.cbssh.net.in.tum.de
