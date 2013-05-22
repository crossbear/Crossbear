#!/bin/bash


if [[ $# -ne 2 ]]; then
	echo "$0 <user name> <database name>"
	exit 1;
fi

psql -U $2 $3 -f- <<'EOF'
-- ASN IP TABLE
CREATE TABLE geo_results (
    id SERIAL PRIMARY KEY,
    ip VARCHAR(64) NOT NULL,
    city VARCHAR(255) NULL,
    region_name VARCHAR(128) NULL,
    region VARCHAR(128) NULL,
    time_zone VARCHAR(64) NULL,
    longitude VARCHAR(64) NULL,
    latitude VARCHAR(64) NULL,
    metro_code VARCHAR(64) NULL,
    country_code VARCHAR(64) NULL,
    country_code3 VARCHAR(64) NULL,
    country_name VARCHAR(64) NULL,
    postal_code VARCHAR(64) NULL,
    dma_code VARCHAR(64) NULL,
    ipStart VARCHAR(64) NULL,
    ipEnd VARCHAR(64) NULL,
    scan_date timestamptz(2) DEFAULT now()
);

EOF

