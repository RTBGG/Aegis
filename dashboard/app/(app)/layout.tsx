"use client";
import { useEffect, useState, type ReactNode } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import type { User, Impersonator } from "@/lib/types";
import { UserContext } from "@/lib/user";
import { Badge } from "@/components/ui";

export default function AppLayout({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<User | null>(null);
  const [impersonator, setImpersonator] = useState<Impersonator | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get<{ user: User; impersonator?: Impersonator }>("/auth/me")
      .then((r) => {
        setUser(r.user);
        setImpersonator(r.impersonator ?? null);
        setLoading(false);
      })
      .catch(() => router.push("/login"));
  }, [router]);

  async function stopImpersonation() {
    try {
      await api.post("/auth/impersonate/stop");
    } finally {
      // Full reload so every session-derived view reflects the restored admin.
      window.location.assign("/admin");
    }
  }

  if (loading) return <div className="grid min-h-screen place-items-center text-slate-400">Loading…</div>;
  if (!user) return null;

  const nav = [
    { href: "/dashboard", label: "Overview" },
    { href: "/domains", label: "Domains" },
    { href: "/settings", label: "Settings" },
  ];
  if (user.role === "admin" || user.role === "superadmin") nav.push({ href: "/admin", label: "Admin" });

  async function logout() {
    try {
      await api.post("/auth/logout");
    } finally {
      router.push("/login");
    }
  }

  return (
    <UserContext.Provider value={user}>
      <div className="flex min-h-screen flex-col">
        {impersonator && (
          <div className="flex items-center justify-between gap-3 bg-amber-500/90 px-4 py-2 text-sm text-black">
            <span>
              Viewing as <strong>{user.email}</strong> — impersonation started by {impersonator.email}
            </span>
            <button
              onClick={stopImpersonation}
              className="rounded bg-black/80 px-3 py-1 text-xs font-medium text-white hover:bg-black"
            >
              Return to admin
            </button>
          </div>
        )}
        <div className="flex min-h-0 flex-1">
        <aside className="flex w-60 shrink-0 flex-col border-r border-edge bg-panel/40 p-4">
          <div className="mb-6 px-2">
            <div className="text-lg font-semibold">Aegis</div>
            <div className="text-xs text-slate-500">edge platform</div>
          </div>
          <nav className="flex-1 space-y-1">
            {nav.map((n) => {
              const active = pathname === n.href || pathname.startsWith(n.href + "/");
              return (
                <Link
                  key={n.href}
                  href={n.href}
                  className={`block rounded-md px-3 py-2 text-sm ${active ? "bg-accent/20 text-white" : "text-slate-300 hover:bg-edge/50"}`}
                >
                  {n.label}
                </Link>
              );
            })}
          </nav>
          <div className="space-y-2 border-t border-edge pt-3 text-sm">
            <div className="truncate px-2 text-slate-400" title={user.email}>
              {user.email}
            </div>
            <div className="px-2">
              <Badge tone={user.role === "user" ? "slate" : "blue"}>{user.role}</Badge>
            </div>
            <button onClick={logout} className="w-full rounded-md px-3 py-2 text-left text-slate-400 hover:bg-edge/50">
              Sign out
            </button>
          </div>
        </aside>
        <main className="flex-1 overflow-x-hidden p-8">
          <div className="mx-auto max-w-5xl">{children}</div>
        </main>
        </div>
      </div>
    </UserContext.Provider>
  );
}
