-- __SCHEMAPLACEHOLDER__ will be replaced by sed for actual schema name
DROP SCHEMA IF EXISTS __SCHEMAPLACEHOLDER__ CASCADE;
CREATE SCHEMA __SCHEMAPLACEHOLDER__;

SET search_path = __SCHEMAPLACEHOLDER__;


CREATE LANGUAGE plpgsql;

CREATE FUNCTION insert_unique_domain(new_fqdn VARCHAR) RETURNS INTEGER AS
$$
DECLARE
	new_index INTEGER;
BEGIN
    SELECT domains.id FROM __SCHEMAPLACEHOLDER__.domains WHERE fqdn = new_fqdn LIMIT 1 INTO new_index;
    IF new_index IS NOT NULL THEN
	RETURN new_index;
    ELSE
	INSERT INTO __SCHEMAPLACEHOLDER__.domains (fqdn) VALUES (new_fqdn) RETURNING id INTO new_index;
	RETURN new_index;
    END IF;
END;
$$ LANGUAGE plpgsql;


-- MAIN TABLE
CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
    fqdn VARCHAR(255) UNIQUE NOT NULL
);

-- ASN IP TABLE
CREATE TABLE geoInfo (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES domains(id),
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
    ipEnd VARCHAR(64) NULL
);