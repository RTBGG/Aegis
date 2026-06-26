"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { Button, Input, Field, ErrorText } from "@/components/ui";

export default function SignupPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      await api.post("/auth/signup", { email, password });
      router.push("/dashboard");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Sign up failed");
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-5 rounded-xl border border-edge bg-panel/60 p-7">
        <div>
          <h1 className="text-xl font-semibold">Create your account</h1>
          <p className="text-sm text-slate-400">Start protecting your domains with Aegis</p>
        </div>
        <Field label="Email">
          <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
        </Field>
        <Field label="Password (min 10 characters)">
          <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={10} />
        </Field>
        <ErrorText>{err}</ErrorText>
        <Button type="submit" disabled={busy}>
          {busy ? "Creating…" : "Create account"}
        </Button>
        <p className="text-center text-sm text-slate-400">
          Already have an account?{" "}
          <Link href="/login" className="text-accent hover:underline">
            Sign in
          </Link>
        </p>
      </form>
    </div>
  );
}
