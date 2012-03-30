--Login as root: su postgres  -> psql
--Login as crossbear: psql --host localhost --username crossbear --dbname crossbear

--SHOW TABLES: \d
--SHOW DATABASES: \l
--SHOW COLUMNS: \d table

--DROP ALL TABLES: SELECT 'DROP TABLE '||c.relname ||' CASCADE;' FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid = c.relowner LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r','') AND n.nspname NOT IN ('pg_catalog', 'pg_toast') AND pg_catalog.pg_table_is_visible(c.oid) ORDER BY 1;
 

CREATE DATABASE crossbear;

CREATE USER crossbear WITH PASSWORD '???';
GRANT ALL ON DATABASE crossbear TO crossbear;

CREATE TABLE CertCache (HostPort VARCHAR(2048), Certificate BYTEA, ValidUntil TIMESTAMP, PRIMARY KEY (HostPort));

CREATE TABLE CertVerifyResultCache (Hash CHAR(64), Bytes BYTEA, ValidUntil TIMESTAMP, PRIMARY KEY (Hash));

CREATE TABLE ServerCerts (Id BIGSERIAL, SHA256DERHash CHAR(64), SHA1DERHash CHAR(40), DERRaw BYTEA, MD5PEMHash CHAR(32), PEMRaw TEXT, CertChainMD5 TEXT, SHA256ChainHash CHAR(64), PRIMARY KEY (Id), UNIQUE(SHA256DERHash,CertChainMD5));
CREATE INDEX SCMd5h ON ServerCerts (MD5PEMHash);
CREATE INDEX SCSHA1h ON ServerCerts (SHA1DERHash);

CREATE TABLE ChainCerts (Id BIGSERIAL, SHA256DERHash CHAR(64),  SHA1DERHash CHAR(40), DERRaw BYTEA, MD5PEMHash CHAR(32), PEMRaw TEXT, PRIMARY KEY (Id), UNIQUE(SHA256DERHash));
CREATE INDEX CCMd5h ON ChainCerts (MD5PEMHash);
CREATE INDEX CCSHA1h ON ChainCerts (SHA1DERHash);

CREATE TABLE CertObservations (Id BIGSERIAL, CertID BIGINT REFERENCES ServerCerts, ServerHostPort VARCHAR(2048), ServerIP VARCHAR(40), TimeOfObservation TIMESTAMP, ObserverType VARCHAR(20), ObserverIP VARCHAR(40), PRIMARY KEY (Id));
CREATE INDEX Cohash ON CertObservations (CertID);
CREATE INDEX Cohost ON CertObservations (ServerHostPort);

CREATE TABLE HuntingTasks (Id SERIAL, TargetHostName VARCHAR(2042), TargetIP VARCHAR(40), TargetPort SMALLINT, TimeOfCreation TIMESTAMP, Active BOOLEAN, PRIMARY KEY (Id));

CREATE TABLE HuntingTaskResults (Id BIGSERIAL, HuntingTaskID INTEGER  REFERENCES HuntingTasks, Trace TEXT, Observation BIGINT REFERENCES CertObservations, PRIMARY KEY (Id));
CREATE INDEX HTRHTI ON HuntingTaskResults (HuntingTaskID);

CREATE TABLE HuntingTaskListCache(Id SERIAL, Data BYTEA, ValidUntil TIMESTAMP, PRIMARY KEY (Id));

CREATE TABLE PublicIPHMacKeys(Id SERIAL, Key BYTEA, ValidUntil TIMESTAMP, PRIMARY KEY (Id) );
INSERT INTO PublicIPHMacKeys (Key, ValidUntil) VALUES (NULL, TIMESTAMP '1900-01-01 00:00'),(NULL, TIMESTAMP '1900-01-01 00:00');

CREATE TABLE ConvergenceNotaries(HostPort VARCHAR(2048), CertID CHAR(64));
INSERT INTO ConvergenceNotaries(HostPort, CertID) VALUES ('notary.thoughtcrime.org:443', '99a33ee0cbb633a2e870c207c30dcbbd0c3b5523ac6c11bd7e2ddb6405ba6671'),('notary2.thoughtcrime.org:443', '5b0fbe8cd008c8c1c9e8ae62ddabc6b50585817094e9a096327e5859a505259f');

CREATE TABLE ConvergenceCertObservations(ServerHostPort VARCHAR(2048), SHA1Hash CHAR(40), FirstObservation TIMESTAMP, LastObservation TIMESTAMP, LastUpdate TIMESTAMP, PRIMARY KEY(ServerHostPort, SHA1Hash));
CREATE INDEX CCOHostName ON ConvergenceCertObservations (ServerHostPort);
CREATE INDEX CCOSHA1 ON ConvergenceCertObservations (SHA1Hash);


CREATE TABLE HuntingTaskRequests(Id BIGSERIAL, RequestingIP VARCHAR(40), TimeOfRequest TIMESTAMP, PRIMARY KEY (Id));
