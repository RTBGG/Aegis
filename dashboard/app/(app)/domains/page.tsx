"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import type { Domain } from "@/lib/types";
import { Button, Input, Card, Badge, ErrorText } from "@/components/ui";

interface AddResult {
  nameservers: string[];
  verification: { txt_name: string; txt_value: string };
}

const statusTone = (s: string): "green" | "amber" | "slate" =>
  s === "active" ? "green" : s === "pending" ? "amber" : "slate";

export default function DomainsPage() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [name, setName] = useState("");
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
      const res = await api.post<AddResult>("/domains", { name: name.trim() });
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
        <form onSubmit={add} className="flex gap-3">
          <Input placeholder="example.com" value={name} onChange={(e) => setName(e.target.value)} required />
          <Button type="submit" disabled={busy}>
            {busy ? "Adding…" : "Add"}
          </Button>
        </form>
        <ErrorText>{err}</ErrorText>
        {added && (
          <div className="mt-4 space-y-2 rounded-lg border border-edge bg-ink/50 p-4 text-sm">
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
