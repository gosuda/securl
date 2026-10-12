ALTER TABLE envelopes
    DROP CONSTRAINT IF EXISTS envelopes_envelope_size,
    ADD CONSTRAINT envelopes_envelope_size CHECK (
        octet_length(envelope) > 0 AND octet_length(envelope) <= 1048576
    );
