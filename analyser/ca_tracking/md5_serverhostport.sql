SELECT md5pemhash, serverhostport FROM servercerts s, certobservations c WHERE s.id = c.certid GROUP BY md5pemhash, serverhostport;
