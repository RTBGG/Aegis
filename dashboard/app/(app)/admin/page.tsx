"use client";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { AdminUser, Edge, Blocklist } from "@/lib/types";
import { Button, Input, Select, Field, Card, Badge, ErrorText } from "@/components/ui";

type Tab = "users" | "edges" | "blocklists" | "enrollment";

export default function AdminPage() {
  const [tab, setTab] = useState<Tab>("users");
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Admin</h1>
      <div className="flex gap-1 border-b border-edge">
        {(["users", "edges", "blocklists", "enrollment"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm capitalize ${tab === t ? "border-b-2 border-accent text-white" : "text-slate-400"}`}
          >
            {t}
          </button>
        ))}
      </div>
      {tab === "users" && <Users />}
      {tab === "edges" && <Edges />}
      {tab === "blocklists" && <Blocklists />}
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
                {u.status === "active" ? (
                  <button onClick={() => setStatus(u, "suspended")} className="text-red-400 hover:underline">
                    suspend
                  </button>
                ) : (
                  <button onClick={() => setStatus(u, "active")} className="text-emerald-400 hover:underline">
                    activate
                  </button>
                )}
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
  useEffect(() => {
    api.get<{ edges: Edge[] }>("/admin/edges").then((r) => setEdges(r.edges ?? [])).catch(() => {});
  }, []);
  return (
    <Card title="Edge fleet">
      <table className="w-full text-sm">
        <thead className="text-left text-xs uppercase text-slate-500">
          <tr>
            <th className="py-2">Name</th>
            <th>IP</th>
            <th>Region</th>
            <th>Status</th>
            <th>Agent</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-edge">
          {edges.map((e) => (
            <tr key={e.id}>
              <td className="py-2 font-medium">{e.name}</td>
              <td className="font-mono">{e.public_ip}</td>
              <td>{e.region}</td>
              <td>
                <Badge tone={e.status === "healthy" ? "green" : e.status === "pending" ? "amber" : "red"}>{e.status}</Badge>
              </td>
              <td className="text-slate-400">{e.agent_version ?? "—"}</td>
              <td className="text-slate-400">{e.last_seen_at ? new Date(e.last_seen_at).toLocaleTimeString() : "—"}</td>
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
