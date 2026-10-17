"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { Domain } from "@/lib/types";
import { Button, Input, Select, Field, Card, Badge, ErrorText } from "@/components/ui";

interface AddResult {
  domain: Domain;
  dns_mode: "ns" | "cname";
  nameservers: string[];
  cname_target: string;
  verification: { txt_name: string; txt_value: string };
}

const statusTone = (s: string): "green" | "amber" | "slate" =>
  s === "active" ? "green" : s === "pending" ? "amber" : "slate";

export default function DomainsPage() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [name, setName] = useState("");
  const [mode, setMode] = useState<"ns" | "cname">("ns");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [added, setAdded] = useState<AddResult | null>(null);

  function load() {
    api.get<{ domains: Domain[] }>("/domains").then((r) => setDomains(r.domains ?? [])).catch(() => {});
  }
  useEffect(load, []);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      const res = await api.post<AddResult>("/domains", { name: name.trim(), dns_mode: mode });
      setAdded(res);
      setName("");
      load();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Failed to add domain");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Domains</h1>

      <Card title="Add a domain">
        <form onSubmit={add} className="grid grid-cols-1 gap-3 md:grid-cols-3 md:items-end">
          <Field label="Domain">
            <Input placeholder="example.com" value={name} onChange={(e) => setName(e.target.value)} required />
          </Field>
          <Field label="DNS connection">
            <Select value={mode} onChange={(e) => setMode(e.target.value as "ns" | "cname")}>
              <option value="ns">Delegate nameservers (NS)</option>
              <option value="cname">CNAME / external DNS</option>
            </Select>
          </Field>
          <Button type="submit" disabled={busy}>
            {busy ? "Adding…" : "Add"}
          </Button>
        </form>
        <ErrorText>{err}</ErrorText>
        {added && (
          <div className="mt-4 space-y-2 rounded-lg border border-edge bg-ink/50 p-4 text-sm">
            {added.dns_mode === "cname" ? (
              <>
                <p className="text-slate-300">
                  Create a <span className="font-mono">CNAME</span> for each hostname you want proxied (e.g.{" "}
                  <span className="font-mono">app.{added.domain.name}</span>) pointing at:
                </p>
                <p className="font-mono text-accent">{added.cname_target}</p>
                <p className="text-xs text-slate-500">
                  A plain CNAME is not allowed at the apex ({added.domain.name}); use an ALIAS/ANAME record if your
                  provider supports it, or onboard a subdomain instead.
                </p>
                <p className="text-slate-400">
                  Then add a TXT record <span className="font-mono">{added.verification.txt_name}</span> ={" "}
                  <span className="font-mono">{added.verification.txt_value}</span> to prove ownership, and click Verify on
                  the domain.
                </p>
              </>
            ) : (
              <>
                <p className="text-slate-300">Point your registrar's nameservers to:</p>
                <ul className="font-mono text-accent">
                  {added.nameservers.map((ns) => (
                    <li key={ns}>{ns}</li>
                  ))}
                </ul>
                <p className="text-slate-400">
                  Or add a TXT record <span className="font-mono">{added.verification.txt_name}</span> ={" "}
                  <span className="font-mono">{added.verification.txt_value}</span>, then click Verify on the domain.
                </p>
              </>
            )}
          </div>
        )}
      </Card>

      <Card title="Your domains">
        {domains.length === 0 ? (
          <p className="text-sm text-slate-400">No domains yet.</p>
        ) : (
          <div className="divide-y divide-edge">
            {domains.map((d) => (
              <Link key={d.id} href={`/domains/${d.id}`} className="flex items-center justify-between py-3 hover:opacity-80">
                <span className="font-medium">{d.name}</span>
                <span className="flex items-center gap-2">
                  {d.paused && <Badge tone="amber">paused</Badge>}
                  <Badge tone={statusTone(d.status)}>{d.status}</Badge>
                </span>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
