CREATE TABLE IF NOT EXISTS session_key(
        session_id INTEGER PRIMARY KEY NOT NULL,
        aes_key BLOB(32) NOT NULL);

CREATE TABLE IF NOT EXISTS log_nonce(
        session_id INTEGER NOT NULL,
        log_id INTEGER NOT NULL,
        nonce BLOB(12) NOT NULL,
        PRIMARY KEY (session_id, log_id));

