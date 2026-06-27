"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { Domain, DnsRecord, DnssecInfo, SecurityPolicy, WafOverride, MetricsSummary } from "@/lib/types";
import { Button, Input, Select, Field, Card, Badge, Toggle, Textarea, ErrorText } from "@/components/ui";

type Tab = "dns" | "dnssec" | "security" | "analytics";
const TAB_LABEL: Record<Tab, string> = { dns: "DNS", dnssec: "DNSSEC", security: "Security", analytics: "Analytics" };
const RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX"];
const canProxy = (t: string) => ["A", "AAAA", "CNAME"].includes(t);

export default function DomainDetail() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [domain, setDomain] = useState<Domain | null>(null);
  const [tab, setTab] = useState<Tab>("dns");
  const [msg, setMsg] = useState("");

  function loadDomain() {
    api.get<{ domain: Domain }>(`/domains/${id}`).then((r) => setDomain(r.domain)).catch(() => {});
  }
  useEffect(loadDomain, [id]);

  async function verify() {
    setMsg("");
    const r = await api.post<{ verified: boolean; reason: string }>(`/domains/${id}/verify`);
    setMsg(r.verified ? `Verified (${r.reason})` : `Not verified: ${r.reason}`);
    loadDomain();
  }
  async function togglePause() {
    if (!domain) return;
    await api.post(`/domains/${id}/pause`, { paused: !domain.paused });
    loadDomain();
  }
  async function remove() {
    if (!confirm("Delete this domain and its DNS zone?")) return;
    await api.del(`/domains/${id}`);
    router.push("/domains");
  }

  if (!domain) return <div className="text-slate-400">Loading…</div>;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">{domain.name}</h1>
          <div className="mt-1 flex items-center gap-2">
            <Badge tone={domain.status === "active" ? "green" : "amber"}>{domain.status}</Badge>
            {domain.paused && <Badge tone="amber">paused</Badge>}
          </div>
        </div>
        <div className="flex gap-2">
          {domain.status !== "active" && <Button onClick={verify}>Verify</Button>}
          <Button variant="ghost" onClick={togglePause}>
            {domain.paused ? "Resume" : "Pause"}
          </Button>
          <Button variant="danger" onClick={remove}>
            Delete
          </Button>
        </div>
      </div>
      {msg && <p className="text-sm text-slate-300">{msg}</p>}

      <div className="flex gap-1 border-b border-edge">
        {(["dns", "dnssec", "security", "analytics"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm ${tab === t ? "border-b-2 border-accent text-white" : "text-slate-400"}`}
          >
            {TAB_LABEL[t]}
          </button>
        ))}
      </div>

      {tab === "dns" && <DnsTab domainId={id} />}
      {tab === "dnssec" && <DnssecTab domainId={id} />}
      {tab === "security" && <SecurityTab domainId={id} />}
      {tab === "analytics" && <AnalyticsTab domainId={id} />}
    </div>
  );
}

function DnsTab({ domainId }: { domainId: string }) {
  const [records, setRecords] = useState<DnsRecord[]>([]);
  const [type, setType] = useState("A");
  const [name, setName] = useState("");
  const [content, setContent] = useState("");
  const [ttl, setTtl] = useState(300);
  const [proxied, setProxied] = useState(true);
  const [err, setErr] = useState("");

  function load() {
    api.get<{ records: DnsRecord[] }>(`/domains/${domainId}/records`).then((r) => setRecords(r.records ?? [])).catch(() => {});
  }
  useEffect(load, [domainId]);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    try {
      await api.post(`/domains/${domainId}/records`, {
        type,
        name: name || "@",
        content,
        ttl,
        proxied: canProxy(type) && proxied,
      });
      setName("");
      setContent("");
      load();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Failed to add record");
    }
  }

  async function toggleProxy(rec: DnsRecord) {
    await api.put(`/records/${rec.id}`, { ...rec, proxied: !rec.proxied });
    load();
  }
  async function del(rec: DnsRecord) {
    await api.del(`/records/${rec.id}`);
    load();
  }

  return (
    <div className="space-y-5">
      <Card title="Add DNS record">
        <form onSubmit={add} className="grid grid-cols-1 gap-3 md:grid-cols-5 md:items-end">
          <Field label="Type">
            <Select value={type} onChange={(e) => setType(e.target.value)}>
              {RECORD_TYPES.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </Select>
          </Field>
          <Field label="Name">
            <Input placeholder="@ or www" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="Content">
            <Input placeholder="1.2.3.4 / demo-origin" value={content} onChange={(e) => setContent(e.target.value)} required />
          </Field>
          <Field label="TTL">
            <Input type="number" value={ttl} onChange={(e) => setTtl(Number(e.target.value))} />
          </Field>
          <Button type="submit">Add</Button>
        </form>
        {canProxy(type) && (
          <div className="mt-3">
            <Toggle checked={proxied} onChange={setProxied} label="Proxied (route through Aegis edge)" />
          </div>
        )}
        <ErrorText>{err}</ErrorText>
      </Card>

      <Card title="Records">
        {records.length === 0 ? (
          <p className="text-sm text-slate-400">No records yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-slate-500">
              <tr>
                <th className="py-2">Type</th>
                <th>Name</th>
                <th>Content</th>
                <th>TTL</th>
                <th>Proxy</th>
                <th></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge">
              {records.map((r) => (
                <tr key={r.id}>
                  <td className="py-2 font-mono">{r.type}</td>
                  <td className="font-mono">{r.name}</td>
                  <td className="font-mono text-slate-300">{r.content}</td>
                  <td>{r.ttl}</td>
                  <td>
                    {canProxy(r.type) ? (
                      <Toggle checked={r.proxied} onChange={() => toggleProxy(r)} />
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="text-right">
                    <button onClick={() => del(r)} className="text-red-400 hover:underline">
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

function DnssecTab({ domainId }: { domainId: string }) {
  const [info, setInfo] = useState<DnssecInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  function load() {
    api.get<{ dnssec: DnssecInfo }>(`/domains/${domainId}/dnssec`).then((r) => setInfo(r.dnssec)).catch(() => {});
  }
  useEffect(load, [domainId]);

  async function enable() {
    setBusy(true);
    setErr("");
    try {
      const r = await api.post<{ dnssec: DnssecInfo }>(`/domains/${domainId}/dnssec`);
      setInfo(r.dnssec);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Failed to enable DNSSEC");
    } finally {
      setBusy(false);
    }
  }
  async function disable() {
    if (!confirm("Disable DNSSEC? Remove the DS record at your registrar FIRST, or resolution will break.")) return;
    setBusy(true);
    setErr("");
    try {
      const r = await api.del<{ dnssec: DnssecInfo }>(`/domains/${domainId}/dnssec`);
      setInfo(r.dnssec);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Failed to disable DNSSEC");
    } finally {
      setBusy(false);
    }
  }

  if (!info) return <div className="text-slate-400">Loading…</div>;

  return (
    <div className="space-y-5">
      <Card
        title="DNSSEC"
        actions={<Badge tone={info.enabled ? "green" : "slate"}>{info.enabled ? "signed" : "unsigned"}</Badge>}
      >
        {!info.enabled ? (
          <div className="space-y-3">
            <p className="text-sm text-slate-400">
              DNSSEC cryptographically signs this zone so resolvers can detect tampering. Enable it here, then publish the
              generated <span className="font-mono">DS</span> record at your domain registrar to complete the chain of trust.
            </p>
            <Button onClick={enable} disabled={busy}>
              {busy ? "Enabling…" : "Enable DNSSEC"}
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-slate-400">
              Zone is signed. Add <span className="text-slate-200">one</span> of these <span className="font-mono">DS</span>{" "}
              records at your registrar — SHA-256 (digest type <span className="font-mono">2</span>) is recommended.
            </p>
            <div>
              <div className="mb-1 text-xs uppercase text-slate-500">DS records</div>
              <pre className="overflow-x-auto rounded-lg border border-edge bg-black/40 p-3 text-xs text-accent">
                {(info.ds ?? []).join("\n") || "—"}
              </pre>
            </div>
            <details>
              <summary className="cursor-pointer text-xs uppercase text-slate-500">DNSKEY</summary>
              <pre className="mt-1 overflow-x-auto rounded-lg border border-edge bg-black/40 p-3 text-xs text-slate-300">
                {(info.dnskey ?? []).join("\n") || "—"}
              </pre>
            </details>
            <Button variant="danger" onClick={disable} disabled={busy}>
              {busy ? "Disabling…" : "Disable DNSSEC"}
            </Button>
          </div>
        )}
        <ErrorText>{err}</ErrorText>
      </Card>
    </div>
  );
}

function SecurityTab({ domainId }: { domainId: string }) {
  const [p, setP] = useState<SecurityPolicy | null>(null);
  const [saved, setSaved] = useState(false);
  const [saveErr, setSaveErr] = useState("");

  useEffect(() => {
    api.get<{ security: SecurityPolicy }>(`/domains/${domainId}/security`).then((r) => setP(r.security)).catch(() => {});
  }, [domainId]);

  if (!p) return <div className="text-slate-400">Loading…</div>;
  const set = (patch: Partial<SecurityPolicy>) => setP({ ...p, ...patch });

  async function save() {
    setSaveErr("");
    try {
      await api.put(`/domains/${domainId}/security`, p);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setSaveErr(e instanceof ApiError ? e.message : "Save failed");
    }
  }

  return (
    <div className="space-y-5">
      <Card title="Web Application Firewall (Coraza + OWASP CRS)">
        <div className="space-y-3">
          <Toggle checked={p.waf_enabled} onChange={(v) => set({ waf_enabled: v })} label="Enable WAF" />
          <div className="grid grid-cols-2 gap-3">
            <Field label="Paranoia level (1–4)">
              <Input type="number" min={1} max={4} value={p.waf_paranoia} onChange={(e) => set({ waf_paranoia: Number(e.target.value) })} />
            </Field>
            <Field label="Mode">
              <Select value={p.waf_mode} onChange={(e) => set({ waf_mode: e.target.value as SecurityPolicy["waf_mode"] })}>
                <option value="block">Block</option>
                <option value="detect">Detect only</option>
              </Select>
            </Field>
          </div>
          <Field label="Custom SecLang rules (advanced)">
            <Textarea
              rows={5}
              spellCheck={false}
              placeholder={`SecRule ARGS:foo "@rx evil" "id:100001,phase:2,deny,status:403,msg:'custom'"`}
              value={p.waf_custom_rules}
              onChange={(e) => set({ waf_custom_rules: e.target.value })}
            />
          </Field>
          <p className="text-xs text-slate-500">
            Appended to the OWASP CRS engine. Only SecRule/SecAction/SecMarker and SecRule(Remove|Update)* directives are
            allowed. Test with Mode = “Detect only” before blocking.
          </p>
        </div>
      </Card>

      <WAFOverrides domainId={domainId} />


      <Card title="Rate limiting & bot protection">
        <div className="space-y-3">
          <Toggle checked={p.rate_limit_enabled} onChange={(v) => set({ rate_limit_enabled: v })} label="Enable rate limiting" />
          <Field label="Requests per minute / IP">
            <Input type="number" value={p.rate_limit_rpm} onChange={(e) => set({ rate_limit_rpm: Number(e.target.value) })} />
          </Field>
          <Field label="Bot protection sensitivity">
            <Select value={p.bot_protection} onChange={(e) => set({ bot_protection: e.target.value as SecurityPolicy["bot_protection"] })}>
              {["off", "low", "medium", "high"].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>
          </Field>
          <Toggle checked={p.challenge_enabled} onChange={(v) => set({ challenge_enabled: v })} label="Proof-of-work challenge for suspicious traffic" />
        </div>
      </Card>

      <Card title="Caching & TLS">
        <div className="space-y-3">
          <Toggle checked={p.cache_enabled} onChange={(v) => set({ cache_enabled: v })} label="Enable edge caching" />
          <Field label="Cache TTL (seconds)">
            <Input type="number" value={p.cache_ttl} onChange={(e) => set({ cache_ttl: Number(e.target.value) })} />
          </Field>
          <Toggle checked={p.https_redirect} onChange={(v) => set({ https_redirect: v })} label="Redirect HTTP → HTTPS" />
        </div>
      </Card>

      <div className="flex items-center gap-3">
        <Button onClick={save}>Save changes</Button>
        {saved && <span className="text-sm text-emerald-300">Saved · pushing to edge…</span>}
        <ErrorText>{saveErr}</ErrorText>
      </div>
    </div>
  );
}

function WAFOverrides({ domainId }: { domainId: string }) {
  const [rows, setRows] = useState<WafOverride[]>([]);
  const [path, setPath] = useState("");
  const [mode, setMode] = useState<WafOverride["mode"]>("off");
  const [excluded, setExcluded] = useState("");
  const [paranoia, setParanoia] = useState("");
  const [err, setErr] = useState("");

  function load() {
    api.get<{ overrides: WafOverride[] }>(`/domains/${domainId}/waf/overrides`).then((r) => setRows(r.overrides ?? [])).catch(() => {});
  }
  useEffect(load, [domainId]);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    try {
      await api.post(`/domains/${domainId}/waf/overrides`, {
        path,
        mode,
        excluded_rules: excluded,
        paranoia: paranoia ? Number(paranoia) : null,
      });
      setPath("");
      setExcluded("");
      setParanoia("");
      load();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Failed to add override");
    }
  }
  async function del(id: string) {
    await api.del(`/domains/${domainId}/waf/overrides/${id}`);
    load();
  }

  return (
    <Card title="Per-route WAF overrides">
      <p className="mb-3 text-sm text-slate-400">
        Relax or disable the WAF for requests under a path prefix — e.g. drop a noisy CRS rule on <span className="font-mono">/api/</span>.
      </p>
      <form onSubmit={add} className="grid grid-cols-1 gap-3 md:grid-cols-5 md:items-end">
        <Field label="Path prefix">
          <Input placeholder="/api/" value={path} onChange={(e) => setPath(e.target.value)} required />
        </Field>
        <Field label="Mode">
          <Select value={mode} onChange={(e) => setMode(e.target.value as WafOverride["mode"])}>
            <option value="off">Disable WAF</option>
            <option value="detect">Detect only</option>
            <option value="inherit">Inherit (just exclusions)</option>
          </Select>
        </Field>
        <Field label="Exclude rule IDs">
          <Input placeholder="942100 942110" value={excluded} onChange={(e) => setExcluded(e.target.value)} />
        </Field>
        <Field label="Paranoia">
          <Input type="number" min={1} max={4} placeholder="—" value={paranoia} onChange={(e) => setParanoia(e.target.value)} />
        </Field>
        <Button type="submit">Add</Button>
      </form>
      <ErrorText>{err}</ErrorText>
      {rows.length > 0 && (
        <table className="mt-4 w-full text-sm">
          <thead className="text-left text-xs uppercase text-slate-500">
            <tr>
              <th className="py-2">Path</th>
              <th>Mode</th>
              <th>Excluded rules</th>
              <th>Paranoia</th>
              <th></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-edge">
            {rows.map((o) => (
              <tr key={o.id}>
                <td className="py-2 font-mono text-slate-300">{o.path}</td>
                <td>
                  <Badge tone={o.mode === "off" ? "red" : o.mode === "detect" ? "amber" : "slate"}>{o.mode}</Badge>
                </td>
                <td className="font-mono text-slate-400">{o.excluded_rules || "—"}</td>
                <td className="text-slate-400">{o.paranoia ?? "—"}</td>
                <td className="text-right">
                  <button onClick={() => del(o.id)} className="text-red-400 hover:underline">
                    delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function AnalyticsTab({ domainId }: { domainId: string }) {
  const [m, setM] = useState<MetricsSummary | null>(null);
  useEffect(() => {
    api.get<{ summary: MetricsSummary }>(`/domains/${domainId}/analytics`).then((r) => setM(r.summary)).catch(() => {});
  }, [domainId]);
  if (!m) return <div className="text-slate-400">Loading…</div>;
  const rows: [string, number][] = [
    ["Requests", m.requests],
    ["Blocked by WAF", m.blocked_waf],
    ["Rate limited / bot blocked", m.blocked_rate],
    ["Challenged", m.challenged],
    ["Cache hits", m.cache_hits],
    ["Cache misses", m.cache_miss],
  ];
  return (
    <Card title="Last 24 hours">
      <table className="w-full text-sm">
        <tbody className="divide-y divide-edge">
          {rows.map(([k, v]) => (
            <tr key={k}>
              <td className="py-2 text-slate-400">{k}</td>
              <td className="text-right font-mono">{v.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
