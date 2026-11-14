CREATE TABLE endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    status TEXT DEFAULT 'Active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE backups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE,
    original_path TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    encrypted_aes_key TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    backed_up_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE,
    attack_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    process_killed BOOLEAN DEFAULT FALSE,
    report_generated BOOLEAN DEFAULT FALSE
);

CREATE TABLE incident_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    corrupted_filepath TEXT NOT NULL,
    corrupted_hash TEXT NOT NULL
);