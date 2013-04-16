#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: makePrefix.sh schema_name [tables|indices]"
    echo "Prints out SQL for creation of schema and tables (or indices)"
    echo "When second argument is empty, it defaults to generate SQL for tables."
    exit 1
fi

#what are we generating - tables or indices?
WHAT="tables"
if [ -n "$2" ]; then
    WHAT="$2"
fi

if [  "$WHAT" '!=' "tables" -a "$WHAT" '!=' "indices" ]; then
    echo "Invalid argument - $WHAT"
    exit 2
fi

sed s/__SCHEMAPLACEHOLDER__/"$1"/g "${0%%/*}/create_${WHAT}_template.sql"