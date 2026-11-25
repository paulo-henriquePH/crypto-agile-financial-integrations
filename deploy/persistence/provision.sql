-- All names below come from the fixed service list, never from requests.
REVOKE CONNECT, TEMPORARY ON DATABASE postgres, template1 FROM PUBLIC;
SELECT format('CREATE ROLE %I LOGIN', :'service')
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'service') \gexec
-- Do not use \gexec with a password: it may echo the expanded statement.
SELECT set_config('lab.service', :'service', false);
DO $$
DECLARE r text := current_setting('lab.service');
BEGIN
    EXECUTE format('ALTER ROLE %I PASSWORD %L', r,
        pg_read_file('/credentials/' || r || '/password'));
END $$;
SELECT format('CREATE DATABASE %I ALLOW_CONNECTIONS false', :'service')
 WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'service') \gexec
REVOKE ALL ON DATABASE :"service" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"service" TO :"service";
ALTER DATABASE :"service" ALLOW_CONNECTIONS true;
