CREATE VIEW serverhostport_to_servercerts AS (SELECT t.pemraw, t.issuer, co.serverhostport, co.certid FROM tests t, certobservations co WHERE co.certid = t.id);
