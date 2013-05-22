#!/bin/bash

if [[ $# -ne 3 ]]; then
	echo "$0 <schema name> <user name> <database name>"
	exit 1;
fi

sed "s/__SCHEMAPLACEHOLDER__/$1/g" << 'EOF' | psql -U $2 $3 -f- 
DROP SCHEMA IF EXISTS __SCHEMAPLACEHOLDER__ CASCADE;
CREATE SCHEMA __SCHEMAPLACEHOLDER__;

SET search_path = __SCHEMAPLACEHOLDER__;


CREATE LANGUAGE plpgsql;

CREATE FUNCTION insert_unique_domain(new_fqdn VARCHAR) RETURNS INTEGER AS
$$
DECLARE
	new_index INTEGER;
BEGIN
    SELECT whois.id FROM __SCHEMAPLACEHOLDER__.whois WHERE fqdn = new_fqdn LIMIT 1 INTO new_index;
    IF new_index IS NOT NULL THEN
	RETURN new_index;
    ELSE
	INSERT INTO __SCHEMAPLACEHOLDER__.whois (fqdn) VALUES (new_fqdn) RETURNING id INTO new_index;
	RETURN new_index;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- This function is necessary to produce NULL values on empty date_str
CREATE FUNCTION to_null_timestamp(date_str VARCHAR, format VARCHAR) RETURNS TIMESTAMP AS
$$
DECLARE
BEGIN
	IF date_str='' THEN
		RETURN NULL;
	ELSE
		RETURN to_timestamp(date_str, format);
	END IF;
END;
$$ LANGUAGE plpgsql;

-- MAIN TABLE
CREATE TABLE __SCHEMAPLACEHOLDER__.whois (
    id SERIAL PRIMARY KEY,
    fqdn VARCHAR(255) UNIQUE NOT NULL,
    update_date TIMESTAMP NULL, 
    create_date TIMESTAMP NULL, 
    expiration_date TIMESTAMP NULL
);

-- MIRROR TABLE
CREATE TABLE __SCHEMAPLACEHOLDER__.whoisNS (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES __SCHEMAPLACEHOLDER__.whois(id),
    nserver VARCHAR(255) NULL
);
EOF
