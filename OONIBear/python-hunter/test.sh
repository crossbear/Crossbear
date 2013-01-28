#!/bin/bash


# take the ooni path as a variable

if [ ! -d "$1" ]
then
    echo "Usage $0 [OONI PATH]"
    exit 1
fi

paths=( $(ls -d "$1/ooni/"*"/") )
joined=$(printf ":%s" "${paths[@]}")

# Why isn't this exported?
PYTHONPATH={$PYTHONPATH}:".$joined"
export PYTHONPATH

echo $PYTHONPATH
echo "Running the test..."

$1/bin/ooniprobe -c OONIBear.py

    
