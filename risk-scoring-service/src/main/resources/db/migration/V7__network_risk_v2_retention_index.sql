CREATE INDEX idx_network_context_retention
    ON network_authentication_contexts (recorded_at, event_id);
