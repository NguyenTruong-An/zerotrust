-- Additive shadow-only state. No existing history is backfilled or reinterpreted.
CREATE TABLE network_authentication_contexts (
    event_id VARCHAR(255) NOT NULL PRIMARY KEY,
    subject_hash VARCHAR(64) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    country_code VARCHAR(2),
    asn_number BIGINT,
    network_hash VARCHAR(64) NOT NULL,
    accuracy_radius_km INT,
    evidence_quality VARCHAR(32) NOT NULL,
    authenticated_at TIMESTAMP(6) NOT NULL,
    recorded_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT fk_network_context_success FOREIGN KEY (event_id)
        REFERENCES authentication_success_events(event_id)
);
CREATE INDEX idx_network_context_subject_client_time
    ON network_authentication_contexts (subject_hash, client_id, authenticated_at);
