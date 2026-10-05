ALTER TABLE known_devices ADD COLUMN revocation_reason VARCHAR(32) NULL;

CREATE TABLE subject_device_trust (
    subject_id VARCHAR(255) NOT NULL PRIMARY KEY,
    generation BIGINT NOT NULL DEFAULT 0,
    pending_operation_id VARCHAR(36) NULL
);

CREATE TABLE device_trust_revocations (
    operation_id VARCHAR(36) NOT NULL PRIMARY KEY,
    subject_id VARCHAR(255) NOT NULL,
    requested_by VARCHAR(255) NOT NULL,
    generation BIGINT NOT NULL,
    revoked_count INT NOT NULL,
    revoked_at TIMESTAMP(6) NOT NULL,
    completed_at TIMESTAMP(6) NULL
);
CREATE INDEX idx_device_revocations_subject ON device_trust_revocations(subject_id, revoked_at);
