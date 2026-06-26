"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";

export default function VerifyPage() {
  const [state, setState] = useState<"working" | "ok" | "fail">("working");

  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get("token");
    if (!token) {
      setState("fail");
      return;
    }
    api
      .post("/auth/verify-email", { token })
      .then(() => setState("ok"))
      .catch(() => setState("fail"));
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm space-y-4 rounded-xl border border-edge bg-panel/60 p-7 text-center">
        {state === "working" && <p className="text-slate-300">Verifying your email…</p>}
        {state === "ok" && <p className="text-emerald-300">Email verified. You can close this tab.</p>}
        {state === "fail" && <p className="text-red-400">This verification link is invalid or expired.</p>}
        <Link href="/dashboard" className="inline-block text-sm text-accent hover:underline">
          Go to dashboard
        </Link>
      </div>
    </div>
  );
}
