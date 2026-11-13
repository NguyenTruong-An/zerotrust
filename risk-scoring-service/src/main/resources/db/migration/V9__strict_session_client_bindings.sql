-- Additive client binding for a verified native SSO session. Original tombstones stay authoritative.
CREATE TABLE security_session_clients (
 session_id VARCHAR(255) NOT NULL,
 client_id VARCHAR(255) NOT NULL,
 security_epoch BIGINT NOT NULL,
 PRIMARY KEY(session_id,client_id),
 CONSTRAINT fk_security_session_client FOREIGN KEY(session_id) REFERENCES security_sessions(session_id)
);
INSERT INTO security_session_clients(session_id,client_id,security_epoch)
 SELECT session_id,client_id,security_epoch FROM security_sessions;
