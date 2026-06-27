"use client";
import { ReactNode, ButtonHTMLAttributes, InputHTMLAttributes, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";

export function Button({
  children,
  variant = "primary",
  ...props
}: { children: ReactNode; variant?: "primary" | "ghost" | "danger" } & ButtonHTMLAttributes<HTMLButtonElement>) {
  const base = "inline-flex items-center justify-center rounded-md px-3.5 py-2 text-sm font-medium transition disabled:opacity-50 disabled:cursor-not-allowed";
  const styles = {
    primary: "bg-accent text-white hover:bg-blue-500",
    ghost: "bg-edge/50 text-slate-200 hover:bg-edge",
    danger: "bg-red-600/90 text-white hover:bg-red-600",
  }[variant];
  return (
    <button className={`${base} ${styles}`} {...props}>
      {children}
    </button>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className="w-full rounded-md border border-edge bg-ink/60 px-3 py-2 text-sm outline-none focus:border-accent"
      {...props}
    />
  );
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className="w-full rounded-md border border-edge bg-ink/60 px-3 py-2 font-mono text-xs outline-none focus:border-accent"
      {...props}
    />
  );
}

export function Select({ children, ...props }: { children: ReactNode } & SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className="w-full rounded-md border border-edge bg-ink/60 px-3 py-2 text-sm outline-none focus:border-accent" {...props}>
      {children}
    </select>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</span>
      {children}
    </label>
  );
}

export function Card({ title, children, actions }: { title?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="rounded-xl border border-edge bg-panel/60 p-5">
      {(title || actions) && (
        <div className="mb-4 flex items-center justify-between">
          {title && <h2 className="text-sm font-semibold text-slate-200">{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </div>
  );
}

export function Badge({ children, tone = "slate" }: { children: ReactNode; tone?: "slate" | "green" | "red" | "amber" | "blue" }) {
  const tones = {
    slate: "bg-slate-700/50 text-slate-300",
    green: "bg-emerald-600/20 text-emerald-300",
    red: "bg-red-600/20 text-red-300",
    amber: "bg-amber-500/20 text-amber-300",
    blue: "bg-blue-600/20 text-blue-300",
  }[tone];
  return <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${tones}`}>{children}</span>;
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={`flex items-center gap-2 text-sm ${checked ? "text-slate-100" : "text-slate-400"}`}
    >
      <span className={`h-5 w-9 rounded-full p-0.5 transition ${checked ? "bg-accent" : "bg-edge"}`}>
        <span className={`block h-4 w-4 rounded-full bg-white transition ${checked ? "translate-x-4" : ""}`} />
      </span>
      {label}
    </button>
  );
}

export function ErrorText({ children }: { children: ReactNode }) {
  if (!children) return null;
  return <p className="text-sm text-red-400">{children}</p>;
}
