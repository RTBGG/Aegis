export interface User {
  id: string;
  email: string;
  role: "user" | "admin" | "superadmin";
  status: string;
  email_verified: boolean;
  totp_enabled: boolean;
  created_at: string;
}

export interface Domain {
  id: string;
  name: string;
  status: "pending" | "active" | "disabled";
  paused: boolean;
  verified_at: string | null;
  created_at: string;
}

export interface DnsRecord {
  id: string;
  domain_id: string;
  type: string;
  name: string;
  content: string;
  ttl: number;
  priority: number | null;
  proxied: boolean;
  updated_at: string;
}

export interface SecurityPolicy {
  https_redirect: boolean;
  min_tls: string;
  waf_enabled: boolean;
  waf_paranoia: number;
  waf_mode: "block" | "detect";
  rate_limit_enabled: boolean;
  rate_limit_rpm: number;
  rate_limit_burst: number;
  cache_enabled: boolean;
  cache_ttl: number;
  bot_protection: "off" | "low" | "medium" | "high";
  challenge_enabled: boolean;
}

export interface MetricsSummary {
  requests: number;
  blocked_waf: number;
  blocked_rate: number;
  challenged: number;
  cache_hits: number;
  cache_miss: number;
  bytes: number;
}

export interface AdminUser {
  id: string;
  email: string;
  role: string;
  status: string;
  email_verified: boolean;
  totp_enabled: boolean;
  created_at: string;
  last_login_at: string | null;
  account_name: string;
  domain_count: number;
}

export interface Edge {
  id: string;
  name: string;
  public_ip: string;
  region: string;
  status: string;
  agent_version: string | null;
  last_seen_at: string | null;
  created_at: string;
}

export interface Blocklist {
  id: string;
  scope: string;
  kind: string;
  value: string;
  action: string;
  note: string | null;
  created_at: string;
}
