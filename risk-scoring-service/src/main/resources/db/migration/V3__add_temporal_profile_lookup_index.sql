CREATE INDEX idx_authentication_success_events_subject_client_time
    ON authentication_success_events (subject_id, client_id, authenticated_at);
