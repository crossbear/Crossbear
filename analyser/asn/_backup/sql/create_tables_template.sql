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
CREATE TABLE asn (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES domains(id),
    ip VARCHAR(64) NOT NULL,
    -- it can happen that there is no ASN in the iptoasn_dat file for that ip
    -- therefore asn has to be allowed to be NULL
    asn INTEGER NULL
);
