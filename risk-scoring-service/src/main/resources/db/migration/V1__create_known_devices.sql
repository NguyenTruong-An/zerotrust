CREATE TABLE known_devices (
    id BIGINT NOT NULL AUTO_INCREMENT,
    subject_id VARCHAR(255) NOT NULL,
    device_fingerprint_hash CHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL,
    first_seen_at TIMESTAMP(6) NOT NULL,
    last_seen_at TIMESTAMP(6) NOT NULL,
    trusted_at TIMESTAMP(6) NULL,
    revoked_at TIMESTAMP(6) NULL,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT pk_known_devices PRIMARY KEY (id),
    CONSTRAINT uk_known_devices_subject_fingerprint
        UNIQUE (subject_id, device_fingerprint_hash),
    CONSTRAINT ck_known_devices_status
        CHECK (status IN ('PENDING', 'TRUSTED', 'REVOKED'))
);

CREATE INDEX idx_known_devices_subject_status
    ON known_devices (subject_id, status);

CREATE INDEX idx_known_devices_last_seen
    ON known_devices (last_seen_at);
