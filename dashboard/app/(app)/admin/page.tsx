"use client";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { AdminUser, Edge, Blocklist, ThreatFeed, EmailConfig, ImpersonationAuditEntry } from "@/lib/types";
import { Button, Input, Select, Field, Card, Badge, Toggle, ErrorText } from "@/components/ui";

type Tab = "users" | "edges" | "blocklists" | "feeds" | "email" | "audit" | "enrollment";

const TAB_LABELS: Record<Tab, string> = {
  users: "Users",
  edges: "Edges",
  blocklists: "Blocklists",
  feeds: "Threat feeds",
  email: "Email",
  audit: "Audit log",
  enrollment: "Enrollment",
};

export default function AdminPage() {
  const [tab, setTab] = useState<Tab>("users");
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Admin</h1>
      <div className="flex gap-1 border-b border-edge">
        {(["users", "edges", "blocklists", "feeds", "email", "audit", "enrollment"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm ${tab === t ? "border-b-2 border-accent text-white" : "text-slate-400"}`}
          >
            {TAB_LABELS[t]}
          </button>
        ))}
      </div>
      {tab === "users" && <Users />}
      {tab === "edges" && <Edges />}
      {tab === "blocklists" && <Blocklists />}
      {tab === "feeds" && <ThreatFeeds />}
      {tab === "email" && <EmailSettings />}
      {tab === "audit" && <AuditLog />}
      {tab === "enrollment" && <Enrollment />}
    </div>
  );
}

function Users() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  function load() {
    api.get<{ users: AdminUser[] }>("/admin/users").then((r) => setUsers(r.users ?? [])).catch(() => {});
  }
  useEffect(load, []);
  async function setStatus(u: AdminUser, status: string) {
    await api.post(`/admin/users/${u.id}/status`, { status });
    load();
  }
  async function impersonate(u: AdminUser) {
    if (!confirm(`Impersonate ${u.email}? Your session will act as this user (audited) until you choose "Return to admin".`)) return;
    await api.post(`/admin/users/${u.id}/impersonate`);
    // Full reload so the layout re-fetches /auth/me as the impersonated user.
    window.location.assign("/dashboard");
  }
  return (
    <Card title={`All users (${users.length})`}>
      <table className="w-full text-sm">
        <thead className="text-left text-xs uppercase text-slate-500">
          <tr>
            <th className="py-2">Email</th>
            <th>Role</th>
            <th>Domains</th>
            <th>2FA</th>
            <th>Status</th>
            <th>Last login</th>
            <th></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-edge">
          {users.map((u) => (
            <tr key={u.id}>
              <td className="py-2">{u.email}</td>
              <td>
                <Badge tone={u.role === "user" ? "slate" : "blue"}>{u.role}</Badge>
              </td>
              <td>{u.domain_count}</td>
              <td>{u.totp_enabled ? "✓" : "—"}</td>
              <td>
                <Badge tone={u.status === "active" ? "green" : "red"}>{u.status}</Badge>
              </td>
              <td className="text-slate-400">{u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : "never"}</td>
              <td className="text-right">
                <div className="flex justify-end gap-3">
                  {u.role === "user" && u.status === "active" && (
                    <button onClick={() => impersonate(u)} className="text-accent hover:underline">
                      impersonate
                    </button>
                  )}
                  {u.status === "active" ? (
                    <button onClick={() => setStatus(u, "suspended")} className="text-red-400 hover:underline">
                      suspend
                    </button>
                  ) : (
                    <button onClick={() => setStatus(u, "active")} className="text-emerald-400 hover:underline">
                      activate
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function Edges() {
  const [edges, setEdges] = useState<Edge[]>([]);
  function load() {
    api.get<{ edges: Edge[] }>("/admin/edges").then((r) => setEdges(r.edges ?? [])).catch(() => {});
  }
  useEffect(load, []);
  async function setWeight(e: Edge, weight: number) {
    if (weight === e.weight || Number.isNaN(weight)) return;
    await api.post(`/admin/edges/${e.id}/weight`, { weight });
    load();
  }
  async function setRegion(e: Edge, region: string) {
    if (region === e.region) return;
    await api.post(`/admin/edges/${e.id}/region`, { region });
    load();
  }
  async function setRevoked(e: Edge, revoked: boolean) {
    if (revoked && !confirm(`Revoke ${e.name}? Its certificate is rejected immediately and it leaves the load balancer.`)) return;
    await api.post(`/admin/edges/${e.id}/revoke`, { revoked });
    load();
  }
  return (
    <Card title="Edge fleet">
      <p className="mb-3 text-sm text-slate-400">
        Region routes clients to the nearest edge (GeoDNS, by continent); weight splits traffic within a pool (sticky per
        client). Weight 0 drains an edge without removing it.
      </p>
      <table className="w-full text-sm">
        <thead className="text-left text-xs uppercase text-slate-500">
          <tr>
            <th className="py-2">Name</th>
            <th>IP</th>
            <th>Region</th>
            <th>Status</th>
            <th>Weight</th>
            <th>Agent</th>
            <th>Enrolled</th>
            <th>Last seen</th>
            <th></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-edge">
          {edges.map((e) => (
            <tr key={e.id}>
              <td className="py-2 font-medium">{e.name}</td>
              <td className="font-mono">{e.public_ip}</td>
              <td>
                <select
                  value={["AF", "AN", "AS", "EU", "NA", "OC", "SA"].includes(e.region) ? e.region : "default"}
                  onChange={(ev) => setRegion(e, ev.target.value)}
                  className="rounded border border-edge bg-ink/60 px-1.5 py-1 text-sm outline-none focus:border-accent"
                >
                  {["default", "AF", "AN", "AS", "EU", "NA", "OC", "SA"].map((rg) => (
                    <option key={rg} value={rg}>
                      {rg}
                    </option>
                  ))}
                </select>
              </td>
              <td>
                {e.revoked_at ? (
                  <Badge tone="red">revoked</Badge>
                ) : (
                  <Badge tone={e.status === "healthy" ? "green" : e.status === "pending" ? "amber" : "red"}>{e.status}</Badge>
                )}
              </td>
              <td>
                <input
                  type="number"
                  min={0}
                  max={1000}
                  defaultValue={e.weight}
                  onBlur={(ev) => setWeight(e, Number(ev.target.value))}
                  onKeyDown={(ev) => ev.key === "Enter" && (ev.target as HTMLInputElement).blur()}
                  className="w-16 rounded border border-edge bg-ink/60 px-2 py-1 text-sm outline-none focus:border-accent"
                />
              </td>
              <td className="text-slate-400">{e.agent_version ?? "—"}</td>
              <td className="text-slate-400">{e.enrolled_at ? new Date(e.enrolled_at).toLocaleDateString() : "local"}</td>
              <td className="text-slate-400">{e.last_seen_at ? new Date(e.last_seen_at).toLocaleTimeString() : "—"}</td>
              <td className="text-right">
                {e.enrolled_at &&
                  (e.revoked_at ? (
                    <button onClick={() => setRevoked(e, false)} className="text-emerald-400 hover:underline">
                      restore
                    </button>
                  ) : (
                    <button onClick={() => setRevoked(e, true)} className="text-red-400 hover:underline">
                      revoke
                    </button>
                  ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function Blocklists() {
  const [items, setItems] = useState<Blocklist[]>([]);
  const [kind, setKind] = useState("ip");
  const [value, setValue] = useState("");
  const [action, setAction] = useState("block");
  const [err, setErr] = useState("");
  function load() {
    api.get<{ blocklists: Blocklist[] }>("/admin/blocklists").then((r) => setItems(r.blocklists ?? [])).catch(() => {});
  }
  useEffect(load, []);
  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    try {
      await api.post("/admin/blocklists", { scope: "global", kind, value, action });
      setValue("");
      load();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Failed");
    }
  }
  async function del(id: string) {
    await api.del(`/admin/blocklists/${id}`);
    load();
  }
  return (
    <div className="space-y-5">
      <Card title="Add blocklist entry">
        <form onSubmit={add} className="grid grid-cols-1 gap-3 md:grid-cols-4 md:items-end">
          <Field label="Kind">
            <Select value={kind} onChange={(e) => setKind(e.target.value)}>
              {["ip", "cidr", "asn", "ja4", "country"].map((k) => (
                <option key={k}>{k}</option>
              ))}
            </Select>
          </Field>
          <Field label="Value">
            <Input placeholder="1.2.3.0/24" value={value} onChange={(e) => setValue(e.target.value)} required />
          </Field>
          <Field label="Action">
            <Select value={action} onChange={(e) => setAction(e.target.value)}>
              <option value="block">block</option>
              <option value="challenge">challenge</option>
            </Select>
          </Field>
          <Button type="submit">Add</Button>
        </form>
        <ErrorText>{err}</ErrorText>
        <p className="mt-2 text-xs text-slate-500">IP/CIDR block entries are enforced at the edge (403). ASN/JA4/country feed the bot-scoring stage.</p>
      </Card>
      <Card title="Entries">
        {items.length === 0 ? (
          <p className="text-sm text-slate-400">No entries.</p>
        ) : (
          <table className="w-full text-sm">
            <tbody className="divide-y divide-edge">
              {items.map((b) => (
                <tr key={b.id}>
                  <td className="py-2 font-mono">{b.kind}</td>
                  <td className="font-mono text-slate-300">{b.value}</td>
                  <td>
                    <Badge tone={b.action === "block" ? "red" : "amber"}>{b.action}</Badge>
                  </td>
                  <td className="text-right">
                    <button onClick={() => del(b.id)} className="text-red-400 hover:underline">
                      delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

function ThreatFeeds() {
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  function load() {
    api.get<{ feeds: ThreatFeed[] }>("/admin/threat-feeds").then((r) => setFeeds(r.feeds ?? [])).catch(() => {});
  }
  useEffect(load, []);
  async function toggle(f: ThreatFeed) {
    setFeeds((prev) => prev.map((x) => (x.id === f.id ? { ...x, enabled: !x.enabled } : x)));
    try {
      await api.put(`/admin/threat-feeds/${f.id}`, { enabled: !f.enabled });
    } finally {
      load();
    }
  }
  async function refresh(f: ThreatFeed) {
    setBusy(f.id);
    try {
      await api.post(`/admin/threat-feeds/${f.id}/refresh`);
      load();
    } finally {
      setBusy(null);
    }
  }
  const total = feeds.filter((f) => f.enabled).reduce((n, f) => n + f.entry_count, 0);
  return (
    <div className="space-y-5">
      <Card title="IP reputation feeds">
        <p className="mb-4 text-sm text-slate-400">
          Free threat-intelligence lists are fetched on a schedule; the union of all{" "}
          <span className="font-medium text-slate-200">enabled</span> feeds is enforced at the edge as a hard 403
          ({total.toLocaleString()} networks active). Disabled feeds keep their data but stop blocking.
        </p>
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-slate-500">
            <tr>
              <th className="py-2">Feed</th>
              <th>Networks</th>
              <th>Last sync</th>
              <th>Status</th>
              <th>Enabled</th>
              <th></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-edge">
            {feeds.map((f) => (
              <tr key={f.id} className="align-top">
                <td className="py-3">
                  <div className="font-medium text-slate-200">{f.name}</div>
                  <div className="break-all font-mono text-xs text-slate-500">{f.url}</div>
                </td>
                <td className="py-3 font-mono">{f.entry_count.toLocaleString()}</td>
                <td className="py-3 text-slate-400">
                  {f.last_synced_at ? new Date(f.last_synced_at).toLocaleString() : "never"}
                </td>
                <td className="py-3">
                  {f.last_status === "ok" ? (
                    <Badge tone="green">ok</Badge>
                  ) : f.last_status === "error" ? (
                    <span title={f.last_error ?? ""}>
                      <Badge tone="red">error</Badge>
                    </span>
                  ) : (
                    <Badge tone="slate">pending</Badge>
                  )}
                </td>
                <td className="py-3">
                  <Toggle checked={f.enabled} onChange={() => toggle(f)} />
                </td>
                <td className="py-3 text-right">
                  <button
                    onClick={() => refresh(f)}
                    disabled={busy === f.id}
                    className="text-accent hover:underline disabled:opacity-50"
                  >
                    {busy === f.id ? "refreshing…" : "refresh now"}
                  </button>
                </td>
              </tr>
            ))}
            {feeds.length === 0 && (
              <tr>
                <td colSpan={6} className="py-4 text-slate-400">
                  No threat feeds configured.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {feeds.some((f) => f.last_status === "error" && f.last_error) && (
          <ErrorText>
            {feeds.find((f) => f.last_status === "error" && f.last_error)?.last_error}
          </ErrorText>
        )}
      </Card>
    </div>
  );
}

function EmailSettings() {
  const [cfg, setCfg] = useState<EmailConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);
  useEffect(() => {
    api.get<EmailConfig>("/admin/email-config").then(setCfg).catch(() => {});
  }, []);
  async function sendTest() {
    setBusy(true);
    setResult(null);
    try {
      const r = await api.post<{ sent_to: string }>("/admin/test-email");
      setResult({ ok: true, msg: `Sent to ${r.sent_to}` });
    } catch (e) {
      setResult({ ok: false, msg: e instanceof ApiError ? e.message : "Send failed" });
    } finally {
      setBusy(false);
    }
  }
  if (!cfg) return <div className="text-slate-400">Loading…</div>;
  const rows: [string, string][] = [
    ["Mode", cfg.mailer === "smtp" ? "SMTP" : "Log (dev — prints to server console)"],
    ["Server", cfg.addr],
    ["From", cfg.from],
    ["TLS", cfg.tls],
    ["Auth", cfg.auth ? "enabled" : "none"],
  ];
  return (
    <Card title="Outbound email (SMTP)">
      <table className="w-full text-sm">
        <tbody className="divide-y divide-edge">
          {rows.map(([k, v]) => (
            <tr key={k}>
              <td className="py-2 text-slate-400">{k}</td>
              <td className="text-right font-mono text-slate-200">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-3 text-xs text-slate-500">
        Configure via environment: <span className="font-mono">MAILER</span>, <span className="font-mono">SMTP_ADDR</span>,{" "}
        <span className="font-mono">SMTP_USERNAME</span>/<span className="font-mono">SMTP_PASSWORD</span>,{" "}
        <span className="font-mono">SMTP_FROM</span>, <span className="font-mono">SMTP_TLS</span>.
      </p>
      <div className="mt-4 flex items-center gap-3">
        <Button onClick={sendTest} disabled={busy}>
          {busy ? "Sending…" : "Send test email"}
        </Button>
        {result && <span className={`text-sm ${result.ok ? "text-emerald-300" : "text-red-400"}`}>{result.msg}</span>}
      </div>
    </Card>
  );
}

function AuditLog() {
  const [entries, setEntries] = useState<ImpersonationAuditEntry[]>([]);
  useEffect(() => {
    api
      .get<{ entries: ImpersonationAuditEntry[] }>("/admin/impersonation-log")
      .then((r) => setEntries(r.entries ?? []))
      .catch(() => {});
  }, []);
  return (
    <Card title="Impersonation audit log">
      <p className="mb-3 text-sm text-slate-400">Every admin impersonation start and stop is recorded here.</p>
      {entries.length === 0 ? (
        <p className="text-sm text-slate-400">No impersonation events yet.</p>
      ) : (
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-slate-500">
            <tr>
              <th className="py-2">When</th>
              <th>Event</th>
              <th>Admin</th>
              <th>Target user</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-edge">
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="py-2 text-slate-400">{new Date(e.created_at).toLocaleString()}</td>
                <td>
                  <Badge tone={e.action.endsWith("start") ? "amber" : "slate"}>
                    {e.action.endsWith("start") ? "start" : "stop"}
                  </Badge>
                </td>
                <td>{e.actor_email ?? "—"}</td>
                <td className="font-mono text-slate-300">{e.target ?? "—"}</td>
                <td className="font-mono text-slate-500">{e.ip ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function Enrollment() {
  const [result, setResult] = useState<{ token: string; install_cmd: string } | null>(null);
  const [note, setNote] = useState("");
  async function generate() {
    setResult(await api.post<{ token: string; install_cmd: string }>("/admin/enrollment-tokens", { note }));
  }
  return (
    <Card title="Add an edge server">
      <p className="mb-3 text-sm text-slate-400">
        Generate a single-use token, then run the printed command on a fresh Debian 13 box to enroll it into the load balancer.
      </p>
      <div className="flex gap-3">
        <Input placeholder="note (optional, e.g. fra-1)" value={note} onChange={(e) => setNote(e.target.value)} />
        <Button onClick={generate}>Generate token</Button>
      </div>
      {result && (
        <div className="mt-4 space-y-2 rounded-lg border border-edge bg-ink/50 p-4">
          <p className="text-xs uppercase text-slate-500">Run on the new edge server (shown once):</p>
          <code className="block break-all rounded bg-black/40 p-3 text-sm text-accent">{result.install_cmd}</code>
        </div>
      )}
    </Card>
  );
}
