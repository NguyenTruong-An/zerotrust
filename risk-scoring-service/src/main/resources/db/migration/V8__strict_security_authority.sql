-- Additive D10 authority. No V1-V7 row is rewritten. Tombstones are not purged.
CREATE TABLE security_subjects (
 subject_id VARCHAR(255) NOT NULL PRIMARY KEY,
 security_epoch BIGINT NOT NULL,
 account_disabled BOOLEAN NOT NULL DEFAULT FALSE,
 pending_operation_id VARCHAR(36),
 updated_at TIMESTAMP(6) NOT NULL
);
CREATE TABLE security_sessions (
 session_id VARCHAR(255) NOT NULL PRIMARY KEY,
 subject_id VARCHAR(255) NOT NULL,
 client_id VARCHAR(255) NOT NULL,
 security_epoch BIGINT NOT NULL,
 revoked BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMP(6) NOT NULL,
 revoked_at TIMESTAMP(6),
 CONSTRAINT fk_security_session_subject FOREIGN KEY(subject_id) REFERENCES security_subjects(subject_id)
);
CREATE INDEX idx_security_sessions_subject ON security_sessions(subject_id);
CREATE TABLE security_operations (
 operation_id VARCHAR(36) NOT NULL PRIMARY KEY,
 subject_id VARCHAR(255) NOT NULL,
 actor_id VARCHAR(255) NOT NULL,
 operation_kind VARCHAR(40) NOT NULL,
 security_epoch BIGINT NOT NULL,
 stage VARCHAR(40) NOT NULL,
 stage_version BIGINT NOT NULL DEFAULT 0,
 grant_hash CHAR(64),
 effect_id VARCHAR(36),
 effect_action VARCHAR(40),
 created_at TIMESTAMP(6) NOT NULL,
 updated_at TIMESTAMP(6) NOT NULL,
 CONSTRAINT fk_security_operation_subject FOREIGN KEY(subject_id) REFERENCES security_subjects(subject_id)
);
CREATE TABLE security_authentication_tickets (
 ticket_hash CHAR(64) NOT NULL PRIMARY KEY,
 subject_id VARCHAR(255) NOT NULL,
 client_id VARCHAR(255) NOT NULL,
 attempt_id VARCHAR(255) NOT NULL,
 security_epoch BIGINT NOT NULL,
 bound_session_id VARCHAR(255),
 expires_at TIMESTAMP(6) NOT NULL,
 CONSTRAINT fk_security_ticket_subject FOREIGN KEY(subject_id) REFERENCES security_subjects(subject_id)
);
CREATE TABLE security_action_proofs (
 proof_id VARCHAR(36) NOT NULL PRIMARY KEY,
 actor_id VARCHAR(255) NOT NULL,
 actor_session_id VARCHAR(255) NOT NULL,
 actor_epoch BIGINT NOT NULL,
 client_id VARCHAR(255) NOT NULL,
 target_id VARCHAR(255) NOT NULL,
 action_name VARCHAR(40) NOT NULL,
 state VARCHAR(20) NOT NULL,
 attempt_id VARCHAR(255),
 factor_method VARCHAR(40),
 factor_at TIMESTAMP(6),
 proof_session_id VARCHAR(255),
 delivery_code_id VARCHAR(255),
 consumed_operation_id VARCHAR(36),
 expires_at TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_security_proofs_actor ON security_action_proofs(actor_id);
