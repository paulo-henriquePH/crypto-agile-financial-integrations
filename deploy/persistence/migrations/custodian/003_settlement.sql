-- Activation and the SCRAM secret are provisioned only by the S2-08 deployment.
CREATE ROLE custodian_runner NOLOGIN;
GRANT CONNECT ON DATABASE custodian TO custodian_runner;

CREATE TABLE settlement_clock (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    fixture catalog_id NOT NULL,
    financial_day date NOT NULL,
    rejection_reason text CHECK (length(rejection_reason) BETWEEN 1 AND 256)
);
CREATE TABLE settlement_cash (
    portfolio_id catalog_id REFERENCES portfolio NOT NULL,
    currency text NOT NULL CHECK (currency='BRL'),
    balance numeric(20,2) NOT NULL CHECK (balance >= 0),
    PRIMARY KEY(portfolio_id,currency)
);
CREATE TABLE settlement_positions (
    portfolio_id catalog_id REFERENCES portfolio NOT NULL,
    asset_id catalog_id REFERENCES asset NOT NULL,
    quantity numeric(30,0) NOT NULL CHECK (quantity >= 0),
    PRIMARY KEY(portfolio_id,asset_id)
);
CREATE TABLE settlement_entries (
    operation_id uuid NOT NULL REFERENCES inbox(operation_id),
    kind text NOT NULL,
    portfolio_id catalog_id NOT NULL,
    currency text,
    asset_id catalog_id,
    amount numeric(20,2),
    quantity numeric(9,0),
    effective_date date NOT NULL CHECK (extract(isodow FROM effective_date) BETWEEN 1 AND 5),
    PRIMARY KEY(operation_id,kind),
    FOREIGN KEY(portfolio_id,currency) REFERENCES settlement_cash,
    FOREIGN KEY(portfolio_id,asset_id) REFERENCES settlement_positions,
    CHECK ((kind='CASH_DEBIT' AND currency IS NOT NULL AND amount IS NOT NULL AND amount > 0
            AND asset_id IS NULL AND quantity IS NULL)
        OR (kind='ASSET_CREDIT' AND asset_id IS NOT NULL AND quantity IS NOT NULL AND quantity > 0
            AND currency IS NULL AND amount IS NULL))
);

GRANT SELECT(financial_day) ON settlement_clock TO custodian;
GRANT SELECT ON inbox, portfolio, asset, counterparty TO custodian_runner;
GRANT SELECT, INSERT ON settlement_clock, settlement_cash, settlement_positions,
    settlement_entries, instruction_events TO custodian_runner;
GRANT UPDATE(financial_day) ON settlement_clock TO custodian_runner;
GRANT UPDATE(balance) ON settlement_cash TO custodian_runner;
GRANT UPDATE(quantity) ON settlement_positions TO custodian_runner;
