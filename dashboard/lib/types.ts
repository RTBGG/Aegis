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

export interface DnssecInfo {
  enabled: boolean;
  ds: string[] | null;
  dnskey: string[] | null;
}

export interface WafOverride {
  id: string;
  path: string;
  mode: "inherit" | "off" | "detect";
  excluded_rules: string;
  paranoia: number | null;
  enabled: boolean;
}

export interface SecurityPolicy {
  https_redirect: boolean;
  min_tls: string;
  waf_enabled: boolean;
  waf_paranoia: number;
  waf_mode: "block" | "detect";
  waf_custom_rules: string;
  rate_limit_enabled: boolean;
  rate_limit_rpm: number;
  rate_limit_burst: number;
  cache_enabled: boolean;
  cache_ttl: number;
  bot_protection: "off" | "low" | "medium" | "high";
  bot_allow_verified: boolean;
  challenge_enabled: boolean;
  challenge_mode: "pow" | "captcha";
  captcha_provider: "" | "turnstile" | "hcaptcha" | "recaptcha";
  captcha_sitekey: string;
  captcha_secret: string;
  captcha_secret_set: boolean;
}

export interface InsightsSummary {
  requests: number;
  visitors: number;
  bytes: number;
  blocked: number;
  challenged: number;
  cached: number;
}

export interface InsightsPoint {
  t: number;
  requests: number;
  visitors: number;
  blocked: number;
  challenged: number;
}

export interface Insights {
  enabled: boolean;
  window: string;
  summary?: InsightsSummary;
  series?: InsightsPoint[];
  top_paths?: { path: string; count: number }[];
  statuses?: { status: number; count: number }[];
  top_countries?: { country: string; count: number }[];
  top_asns?: { asn: number; org: string; count: number }[];
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

export interface Impersonator {
  id: string;
  email: string;
}

export interface EmailConfig {
  mailer: string;
  addr: string;
  from: string;
  tls: string;
  auth: boolean;
}

export interface ImpersonationAuditEntry {
  id: number;
  action: string;
  actor_email: string | null;
  target: string | null;
  ip: string | null;
  created_at: string;
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

export interface ThreatFeed {
  id: string;
  slug: string;
  name: string;
  url: string;
  format: string;
  enabled: boolean;
  refresh_interval: number;
  last_synced_at: string | null;
  last_status: string | null;
  last_error: string | null;
  entry_count: number;
}
