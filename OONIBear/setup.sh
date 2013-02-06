#!/bin/sh

if [ ! -d "$1" ]
then
    echo "Usage $0 [OONI PATH]"
    exit 1
fi


ln -s PyHunter $1/ooni/
ln -s cbutils ./PyHunter/
ln -s OONIBear.py $1/
ln -s cb.conf $1/
ln -s cbserver.crt $1/
ln -s ooniprobe.conf $1/
ln -s cbmessaging ./PyHunter/


echo "All has been set up chief!"
