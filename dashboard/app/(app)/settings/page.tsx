"use client";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { User } from "@/lib/types";
import { Button, Input, Field, Card, Badge, ErrorText } from "@/components/ui";

export default function SettingsPage() {
  const [me, setMe] = useState<User | null>(null);
  const [setup, setSetup] = useState<{ secret: string; otpauth_url: string } | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [ok, setOk] = useState("");

  function loadMe() {
    api.get<{ user: User }>("/auth/me").then((r) => setMe(r.user)).catch(() => {});
  }
  useEffect(loadMe, []);

  async function startSetup() {
    setErr("");
    try {
      setSetup(await api.post<{ secret: string; otpauth_url: string }>("/auth/mfa/setup"));
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Failed");
    }
  }
  async function enable() {
    setErr("");
    try {
      await api.post("/auth/mfa/enable", { code });
      setSetup(null);
      setCode("");
      setOk("Two-factor authentication enabled.");
      loadMe();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Invalid code");
    }
  }
  async function disable() {
    setErr("");
    try {
      await api.post("/auth/mfa/disable", { password });
      setPassword("");
      setOk("Two-factor authentication disabled.");
      loadMe();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Wrong password");
    }
  }

  if (!me) return <div className="text-slate-400">Loading…</div>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Settings</h1>

      <Card title="Account">
        <dl className="space-y-2 text-sm">
          <div className="flex justify-between">
            <dt className="text-slate-400">Email</dt>
            <dd>{me.email}</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-slate-400">Role</dt>
            <dd>
              <Badge tone="blue">{me.role}</Badge>
            </dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-slate-400">Email verified</dt>
            <dd>{me.email_verified ? <Badge tone="green">yes</Badge> : <Badge tone="amber">no</Badge>}</dd>
          </div>
        </dl>
      </Card>

      <Card title="Two-factor authentication (TOTP)">
        {ok && <p className="mb-3 text-sm text-emerald-300">{ok}</p>}
        {me.totp_enabled ? (
          <div className="space-y-3">
            <p className="text-sm text-slate-300">
              <Badge tone="green">enabled</Badge> Your account is protected with an authenticator app.
            </p>
            <Field label="Confirm password to disable">
              <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
            <Button variant="danger" onClick={disable}>
              Disable 2FA
            </Button>
          </div>
        ) : setup ? (
          <div className="space-y-3">
            <p className="text-sm text-slate-300">Add this secret to your authenticator app:</p>
            <div className="break-all rounded-md border border-edge bg-ink/50 p-3 font-mono text-sm text-accent">{setup.secret}</div>
            <p className="break-all text-xs text-slate-500">{setup.otpauth_url}</p>
            <Field label="Enter the 6-digit code to confirm">
              <Input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} />
            </Field>
            <Button onClick={enable}>Enable 2FA</Button>
          </div>
        ) : (
          <Button onClick={startSetup}>Set up 2FA</Button>
        )}
        <ErrorText>{err}</ErrorText>
      </Card>
    </div>
  );
}
