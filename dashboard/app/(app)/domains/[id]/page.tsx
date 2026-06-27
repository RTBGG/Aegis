"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { Domain, DnsRecord, DnssecInfo, SecurityPolicy, WafOverride, Insights, InsightsPoint } from "@/lib/types";
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
          <Toggle
            checked={p.bot_allow_verified}
            onChange={(v) => set({ bot_allow_verified: v })}
            label="Allow verified search-engine bots (Googlebot, Bingbot, …)"
          />
          <Toggle checked={p.challenge_enabled} onChange={(v) => set({ challenge_enabled: v })} label="Challenge suspicious traffic" />
          {p.challenge_enabled && (
            <div className="space-y-3 rounded-lg border border-edge bg-ink/30 p-3">
              <Field label="Challenge type">
                <Select value={p.challenge_mode} onChange={(e) => set({ challenge_mode: e.target.value as SecurityPolicy["challenge_mode"] })}>
                  <option value="pow">Managed (proof-of-work, no interaction)</option>
                  <option value="captcha">CAPTCHA</option>
                </Select>
              </Field>
              {p.challenge_mode === "captcha" && (
                <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                  <Field label="Provider">
                    <Select
                      value={p.captcha_provider || "turnstile"}
                      onChange={(e) => set({ captcha_provider: e.target.value as SecurityPolicy["captcha_provider"] })}
                    >
                      <option value="turnstile">Cloudflare Turnstile</option>
                      <option value="hcaptcha">hCaptcha</option>
                      <option value="recaptcha">reCAPTCHA</option>
                    </Select>
                  </Field>
                  <Field label="Site key">
                    <Input value={p.captcha_sitekey} onChange={(e) => set({ captcha_sitekey: e.target.value })} placeholder="0x4AAA…" />
                  </Field>
                  <Field label="Secret key">
                    <Input
                      type="password"
                      value={p.captcha_secret}
                      onChange={(e) => set({ captcha_secret: e.target.value })}
                      placeholder={p.captcha_secret_set ? "•••••••• (saved — leave blank to keep)" : "secret key"}
                    />
                  </Field>
                </div>
              )}
            </div>
          )}
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

const fmtNum = (n: number) => n.toLocaleString();
function fmtBytes(n: number): string {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

function AnalyticsTab({ domainId }: { domainId: string }) {
  const [data, setData] = useState<Insights | null>(null);
  const [window, setWindow] = useState<"24h" | "7d">("24h");

  useEffect(() => {
    setData(null);
    api.get<Insights>(`/domains/${domainId}/insights?window=${window}`).then(setData).catch(() => {});
  }, [domainId, window]);

  if (!data) return <div className="text-slate-400">Loading…</div>;

  if (!data.enabled) {
    return (
      <Card title="Analytics">
        <p className="text-sm text-slate-400">
          Detailed analytics require ClickHouse. Set <span className="font-mono">CLICKHOUSE_URL</span> and restart the control
          plane to see per-request traffic, unique visitors, top paths and status codes.
        </p>
      </Card>
    );
  }

  const s = data.summary ?? { requests: 0, visitors: 0, bytes: 0, blocked: 0, challenged: 0, cached: 0 };
  const series = data.series ?? [];
  const cacheRate = s.requests > 0 ? Math.round((s.cached / s.requests) * 100) : 0;
  const topPaths = data.top_paths ?? [];
  const maxPath = Math.max(1, ...topPaths.map((p) => p.count));
  const statuses = data.statuses ?? [];
  const countries = data.top_countries ?? [];
  const maxCountry = Math.max(1, ...countries.map((c) => c.count));
  const asns = data.top_asns ?? [];
  const maxAsn = Math.max(1, ...asns.map((a) => a.count));

  return (
    <div className="space-y-5">
      <div className="flex justify-end gap-1">
        {(["24h", "7d"] as const).map((wnd) => (
          <button
            key={wnd}
            onClick={() => setWindow(wnd)}
            className={`rounded-md px-3 py-1 text-sm ${window === wnd ? "bg-accent text-white" : "bg-edge/50 text-slate-300"}`}
          >
            {wnd === "24h" ? "Last 24h" : "Last 7 days"}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
        <Stat label="Requests" value={fmtNum(s.requests)} />
        <Stat label="Unique visitors" value={fmtNum(s.visitors)} />
        <Stat label="Bandwidth" value={fmtBytes(s.bytes)} />
        <Stat label="Blocked" value={fmtNum(s.blocked)} tone="red" />
        <Stat label="Challenged" value={fmtNum(s.challenged)} tone="amber" />
        <Stat label="Cache hit rate" value={`${cacheRate}%`} />
      </div>

      <Card title="Traffic">
        <TimeChart points={series} />
        <div className="mt-3 flex gap-4 text-xs text-slate-400">
          <Legend color="#5b8cff" label="requests" />
          <Legend color="#f87171" label="blocked" />
          <Legend color="#fbbf24" label="challenged" />
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
        <Card title="Top paths">
          {topPaths.length === 0 ? (
            <p className="text-sm text-slate-400">No data yet.</p>
          ) : (
            <div className="space-y-2">
              {topPaths.map((p) => (
                <div key={p.path} className="text-sm">
                  <div className="flex justify-between gap-2">
                    <span className="truncate font-mono text-slate-300" title={p.path}>
                      {p.path}
                    </span>
                    <span className="font-mono text-slate-400">{fmtNum(p.count)}</span>
                  </div>
                  <div className="mt-1 h-1.5 rounded bg-edge/50">
                    <div className="h-1.5 rounded bg-accent" style={{ width: `${(p.count / maxPath) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card title="Status codes">
          {statuses.length === 0 ? (
            <p className="text-sm text-slate-400">No data yet.</p>
          ) : (
            <table className="w-full text-sm">
              <tbody className="divide-y divide-edge">
                {statuses.map((st) => (
                  <tr key={st.status}>
                    <td className="py-2">
                      <Badge tone={st.status < 300 ? "green" : st.status < 400 ? "blue" : st.status < 500 ? "amber" : "red"}>
                        {st.status}
                      </Badge>
                    </td>
                    <td className="text-right font-mono text-slate-400">{fmtNum(st.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
        <Card title="Top countries">
          {countries.length === 0 ? (
            <p className="text-sm text-slate-400">No geo data yet.</p>
          ) : (
            <div className="space-y-2">
              {countries.map((c) => (
                <BarRow key={c.country} label={`${flagEmoji(c.country)} ${c.country}`} count={c.count} max={maxCountry} />
              ))}
            </div>
          )}
        </Card>
        <Card title="Top networks (ASN)">
          {asns.length === 0 ? (
            <p className="text-sm text-slate-400">No geo data yet.</p>
          ) : (
            <div className="space-y-2">
              {asns.map((a) => (
                <BarRow key={a.asn} label={a.org || `AS${a.asn}`} count={a.count} max={maxAsn} />
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

// flagEmoji turns a 2-letter country code into its regional-indicator flag.
function flagEmoji(cc: string): string {
  if (!/^[A-Za-z]{2}$/.test(cc)) return "🏳";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((ch) => 127397 + ch.charCodeAt(0)));
}

function BarRow({ label, count, max }: { label: string; count: number; max: number }) {
  return (
    <div className="text-sm">
      <div className="flex justify-between gap-2">
        <span className="truncate text-slate-300" title={label}>
          {label}
        </span>
        <span className="font-mono text-slate-400">{count.toLocaleString()}</span>
      </div>
      <div className="mt-1 h-1.5 rounded bg-edge/50">
        <div className="h-1.5 rounded bg-accent" style={{ width: `${(count / max) * 100}%` }} />
      </div>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: "red" | "amber" }) {
  const color = tone === "red" ? "text-red-300" : tone === "amber" ? "text-amber-300" : "text-white";
  return (
    <div className="rounded-xl border border-edge bg-panel/60 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${color}`}>{value}</div>
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="inline-block h-2 w-2 rounded-full" style={{ background: color }} />
      {label}
    </span>
  );
}

function TimeChart({ points }: { points: InsightsPoint[] }) {
  if (points.length === 0) return <p className="text-sm text-slate-400">No traffic in this window yet.</p>;
  const W = 760;
  const H = 200;
  const pad = 28;
  const n = points.length;
  const maxY = Math.max(1, ...points.map((p) => p.requests));
  const x = (i: number) => pad + (i * (W - 2 * pad)) / Math.max(1, n - 1);
  const y = (v: number) => H - pad - (v * (H - 2 * pad)) / maxY;
  const path = (sel: (p: InsightsPoint) => number) =>
    points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(sel(p)).toFixed(1)}`).join(" ");
  const area = `${path((p) => p.requests)} L${x(n - 1).toFixed(1)},${H - pad} L${x(0).toFixed(1)},${H - pad} Z`;
  const fmtT = (t: number) => new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" });

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="requests over time">
      <line x1={pad} y1={H - pad} x2={W - pad} y2={H - pad} stroke="#2b3650" strokeWidth="1" />
      <path d={area} fill="#5b8cff" fillOpacity="0.15" />
      <path d={path((p) => p.requests)} fill="none" stroke="#5b8cff" strokeWidth="2" />
      <path d={path((p) => p.blocked)} fill="none" stroke="#f87171" strokeWidth="1.5" />
      <path d={path((p) => p.challenged)} fill="none" stroke="#fbbf24" strokeWidth="1.5" />
      <text x={pad} y={H - 8} fill="#9aa6c0" fontSize="10">
        {fmtT(points[0].t)}
      </text>
      <text x={W - pad} y={H - 8} fill="#9aa6c0" fontSize="10" textAnchor="end">
        {fmtT(points[n - 1].t)}
      </text>
      <text x={pad} y={14} fill="#9aa6c0" fontSize="10">
        peak {maxY.toLocaleString()}/bucket
      </text>
    </svg>
  );
}
