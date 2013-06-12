#!/bin/bash

psql -U $2 $3 -f- <<'EOF'
create table whois_results (
	id SERIAL PRIMARY KEY,
	ip VARCHAR(64) NOT NULL,
	whois_data TEXT,
	scan_date timestamptz(2) DEFAULT now()
);
EOF
