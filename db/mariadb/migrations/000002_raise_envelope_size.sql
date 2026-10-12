-- One atomic ALTER: the constraint exists both before and after it, so a retry
-- after a failure to record the version row stays safe. Plain DROP CONSTRAINT is
-- used because sqlc's MySQL parser rejects MariaDB's DROP CONSTRAINT IF EXISTS.
ALTER TABLE envelopes
    DROP CONSTRAINT envelopes_envelope_size,
    ADD CONSTRAINT envelopes_envelope_size CHECK (
        OCTET_LENGTH(envelope) > 0 AND OCTET_LENGTH(envelope) <= 1048576
    );
