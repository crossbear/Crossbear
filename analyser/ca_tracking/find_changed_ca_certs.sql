SELECT s1.certid FROM serverhostport_to_servercerts s1, serverhostport_to_servercerts s2 WHERE s1.serverhostport = s2.serverhostport AND s1.issuer != s2.issuer GROUP BY s1.certid;
