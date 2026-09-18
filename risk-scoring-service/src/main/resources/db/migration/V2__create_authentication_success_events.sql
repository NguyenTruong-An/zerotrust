CREATE TABLE authentication_success_events (
    id BIGINT NOT NULL AUTO_INCREMENT,
    event_id VARCHAR(255) NOT NULL,
    subject_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    authenticated_at TIMESTAMP(6) NOT NULL,
    recorded_at TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_authentication_success_events PRIMARY KEY (id),
    CONSTRAINT uk_authentication_success_events_event_id UNIQUE (event_id)
);

CREATE INDEX idx_authentication_success_events_subject_time
    ON authentication_success_events (subject_id, authenticated_at);

CREATE INDEX idx_authentication_success_events_recorded_at
    ON authentication_success_events (recorded_at);
