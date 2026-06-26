"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { MetricsSummary, Domain } from "@/lib/types";
import { Card } from "@/components/ui";

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-xl border border-edge bg-panel/60 p-5">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

const fmt = (n: number) => n.toLocaleString();

export default function DashboardPage() {
  const [m, setM] = useState<MetricsSummary | null>(null);
  const [domains, setDomains] = useState<Domain[]>([]);

  useEffect(() => {
    api.get<{ summary: MetricsSummary }>("/analytics/overview").then((r) => setM(r.summary)).catch(() => {});
    api.get<{ domains: Domain[] }>("/domains").then((r) => setDomains(r.domains ?? [])).catch(() => {});
  }, []);

  const totalCache = m ? m.cache_hits + m.cache_miss : 0;
  const hitRate = totalCache > 0 ? Math.round((m!.cache_hits / totalCache) * 100) : 0;
  const active = domains.filter((d) => d.status === "active").length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Overview</h1>
        <p className="text-sm text-slate-400">Traffic and protection across your domains (last 24h)</p>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Requests" value={m ? fmt(m.requests) : "—"} />
        <Stat label="Blocked" value={m ? fmt(m.blocked_waf + m.blocked_rate) : "—"} hint="WAF + rate limit" />
        <Stat label="Challenged" value={m ? fmt(m.challenged) : "—"} hint="bot challenges" />
        <Stat label="Cache hit rate" value={m ? `${hitRate}%` : "—"} />
      </div>

      <Card title="Domains">
        {domains.length === 0 ? (
          <p className="text-sm text-slate-400">
            No domains yet. <a href="/domains" className="text-accent hover:underline">Add your first domain →</a>
          </p>
        ) : (
          <p className="text-sm text-slate-300">
            {domains.length} domain{domains.length === 1 ? "" : "s"} · {active} active
          </p>
        )}
      </Card>
    </div>
  );
}
