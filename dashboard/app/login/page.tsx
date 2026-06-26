"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { Button, Input, Field, ErrorText } from "@/components/ui";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfa, setMfa] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      if (mfa) {
        await api.post("/auth/mfa", { code });
      } else {
        const res = await api.post<{ mfa_required?: boolean }>("/auth/login", { email, password });
        if (res.mfa_required) {
          setMfa(true);
          setBusy(false);
          return;
        }
      }
      router.push("/dashboard");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Login failed");
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-5 rounded-xl border border-edge bg-panel/60 p-7">
        <div>
          <h1 className="text-xl font-semibold">Aegis</h1>
          <p className="text-sm text-slate-400">{mfa ? "Enter your authenticator code" : "Sign in to your account"}</p>
        </div>
        {!mfa ? (
          <>
            <Field label="Email">
              <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
            </Field>
            <Field label="Password">
              <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </Field>
          </>
        ) : (
          <Field label="6-digit code">
            <Input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} required autoFocus />
          </Field>
        )}
        <ErrorText>{err}</ErrorText>
        <Button type="submit" disabled={busy} >
          {busy ? "Please wait…" : mfa ? "Verify" : "Sign in"}
        </Button>
        {!mfa && (
          <p className="text-center text-sm text-slate-400">
            No account?{" "}
            <Link href="/signup" className="text-accent hover:underline">
              Create one
            </Link>
          </p>
        )}
      </form>
    </div>
  );
}
