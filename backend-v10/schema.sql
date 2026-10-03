-- Shared Web Shop + DOOM database. One user, one subscription, both apps.
-- Entitlements are read from here. The frontend cannot invent a plan.

CREATE TYPE doom_tier AS ENUM ('free', 'basic', 'pro', 'business', 'enterprise');
CREATE TYPE member_role AS ENUM ('owner', 'admin', 'operator', 'viewer');
CREATE TYPE member_status AS ENUM ('invited', 'active', 'suspended', 'removed');

CREATE TABLE users (
  user_id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE subscriptions (
  user_id TEXT PRIMARY KEY REFERENCES users(user_id),
  tier doom_tier NOT NULL DEFAULT 'free',
  status TEXT NOT NULL DEFAULT 'active',
  anchor_date DATE NOT NULL DEFAULT CURRENT_DATE,
  provider TEXT,
  provider_ref TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE entitlements (
  user_id TEXT PRIMARY KEY REFERENCES users(user_id),
  monthly_tokens BIGINT NOT NULL,
  tokens_remaining BIGINT NOT NULL,
  daily_tool_limit INTEGER NOT NULL,
  daily_tools_remaining INTEGER NOT NULL,
  seats INTEGER NOT NULL,
  storage_bytes BIGINT NOT NULL,
  local_unlocked BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE workspaces (
  workspace_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE memberships (
  membership_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  user_id TEXT REFERENCES users(user_id),
  email TEXT NOT NULL,
  role member_role NOT NULL,
  status member_status NOT NULL DEFAULT 'invited',
  UNIQUE (workspace_id, email)
);

CREATE TABLE company_rules (
  workspace_id TEXT PRIMARY KEY REFERENCES workspaces(workspace_id),
  rules JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE chats (
  chat_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  workspace_id TEXT REFERENCES workspaces(workspace_id),
  title TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE messages (
  message_id BIGSERIAL PRIMARY KEY,
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  role TEXT NOT NULL,
  body TEXT NOT NULL,
  power TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE files (
  file_id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(user_id),
  workspace_id TEXT REFERENCES workspaces(workspace_id),
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  storage_key TEXT NOT NULL,
  bytes BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ai_employees (
  employee_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  name TEXT NOT NULL,
  function_text TEXT,
  automations TEXT,
  connectors TEXT,
  workflow TEXT
);

CREATE TABLE sessions (
  session_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  client TEXT NOT NULL CHECK (client IN ('web', 'app')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- V10 production hardening: authenticated sessions, persistent provider connections,
-- approval gates, audit trail, granular workspace permissions and invitations.
CREATE TABLE IF NOT EXISTS tool_connections (
  connection_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  workspace_id TEXT REFERENCES workspaces(workspace_id),
  app_name TEXT NOT NULL,
  provider_account_id TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, app_name)
);
CREATE TABLE IF NOT EXISTS approval_requests (
  approval_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  workspace_id TEXT REFERENCES workspaces(workspace_id),
  app_name TEXT NOT NULL,
  action TEXT NOT NULL,
  params JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS audit_logs (
  audit_id BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  workspace_id TEXT REFERENCES workspaces(workspace_id),
  event TEXT NOT NULL,
  app_name TEXT,
  action TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS workspace_permissions (
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  role TEXT NOT NULL,
  app_name TEXT NOT NULL,
  action TEXT NOT NULL,
  effect TEXT NOT NULL DEFAULT 'allow',
  PRIMARY KEY(workspace_id, role, app_name, action)
);
CREATE TABLE IF NOT EXISTS workspace_invitations (
  invitation_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  invited_email TEXT NOT NULL,
  role TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_by TEXT NOT NULL REFERENCES users(user_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  accepted_at TIMESTAMPTZ
);
