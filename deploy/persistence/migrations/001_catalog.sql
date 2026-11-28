-- Applied to each independent database by its operator in a single transaction.
CREATE DOMAIN catalog_id AS text CHECK (VALUE COLLATE "C" ~ '^[A-Za-z0-9_-]{1,64}$');
CREATE TABLE portfolio (
    id catalog_id PRIMARY KEY,
    custodian_id catalog_id NOT NULL,
    administrator_id catalog_id NOT NULL
);
CREATE TABLE portfolio_access (
    manager_id catalog_id NOT NULL,
    portfolio_id catalog_id REFERENCES portfolio NOT NULL,
    PRIMARY KEY (manager_id, portfolio_id)
);
CREATE TABLE asset (
    id catalog_id PRIMARY KEY,
    issuer_id catalog_id NOT NULL,
    asset_type text NOT NULL CHECK (asset_type = 'DEBENTURE')
);
CREATE TABLE counterparty (id catalog_id PRIMARY KEY);

-- Synthetic reference set from fixtures/boletas/references.json.
INSERT INTO portfolio VALUES ('FUNDO-ALFA', 'CUSTODIANTE-GAMA', 'ADMINISTRADOR-DELTA');
INSERT INTO portfolio_access VALUES ('GESTORA-ALFA', 'FUNDO-ALFA');
INSERT INTO asset VALUES ('DEB-FICTICIA-01', 'EMISSOR-01', 'DEBENTURE');
INSERT INTO counterparty VALUES ('INSTITUICAO-BETA');
GRANT SELECT ON portfolio, portfolio_access, asset, counterparty TO :"service";
