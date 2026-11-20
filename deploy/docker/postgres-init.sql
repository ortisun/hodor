-- Development only. Creates the group roles the migrations expect and one
-- login role per binary, the way an operator would provision them. The
-- passwords are placeholders for local use.

CREATE ROLE hodor_app NOLOGIN;
CREATE ROLE hodor_platform NOLOGIN;

-- The server only ever acts inside one tenant.
CREATE ROLE hodor_server LOGIN PASSWORD 'dev-server' IN ROLE hodor_app;

-- The worker finds work across tenants, then handles it inside one.
CREATE ROLE hodor_worker_platform LOGIN PASSWORD 'dev-worker' IN ROLE hodor_platform;
CREATE ROLE hodor_worker LOGIN PASSWORD 'dev-worker' IN ROLE hodor_app;
