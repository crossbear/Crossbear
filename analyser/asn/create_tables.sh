#!/bin/bash



if [[ $# -ne 2 ]]; then
	echo "$0 <user name> <database name>"
	exit 1;
fi

psql -U $2 $3 -f- <<'EOF'
CREATE TABLE asn_results (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(64) NOT NULL,
    -- it can happen that there is no ASN in the iptoasn_dat file for that ip
    -- therefore asn has to be allowed to be NULL
    asn INTEGER NULL,
    scan_date timestamptz(2) DEFAULT now()
);
EOF
