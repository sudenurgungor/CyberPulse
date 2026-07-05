CREATE TABLE attacks (
    id SERIAL PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL,
    source_ip VARCHAR(50) NOT NULL,
    target_ip VARCHAR(50),
    source_port INTEGER,
    target_port INTEGER,
    protocol VARCHAR(20),
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    status VARCHAR(30) DEFAULT 'detected',
    action_taken VARCHAR(50) DEFAULT 'none',
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blocked_ips (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(50) NOT NULL UNIQUE,
    block_reason VARCHAR(100),
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ip_lists (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(50) NOT NULL,
    list_type VARCHAR(20) NOT NULL,
    reason VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (ip_address, list_type)
);