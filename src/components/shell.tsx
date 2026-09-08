import { Link, useNavigate, useRouter } from "@tanstack/react-router";
import { useEffect, useState, type ReactNode } from "react";
import { getMe, logout } from "~/server/functions";
import type { SafeUser } from "~/server/types";

export function useMe() {
  const [me, setMe] = useState<SafeUser | null | undefined>(undefined);
  const refresh = async () => {
    try {
      const r = await getMe();
      setMe(r.user);
    } catch {
      setMe(null);
    }
  };
  useEffect(() => {
    void refresh();
  }, []);
  return { me, refresh };
}

export function Shell({ children }: { children: ReactNode }) {
  const { me, refresh } = useMe();
  const navigate = useNavigate();
  const router = useRouter();

  const doLogout = async () => {
    await logout();
    await refresh();
    await navigate({ to: "/" });
    router.invalidate();
  };

  return (
    <div className="min-h-dvh bg-[#0a0c10] font-mono text-[#c9d4e3]">
      <header className="border-b border-[#1d2532] bg-[#0d1117]/90">
        <div className="mx-auto flex max-w-6xl items-center gap-4 px-4 py-3">
          <Link to="/" className="flex items-center gap-2">
            <span className="inline-block h-3 w-3 rounded-sm bg-[#e5484d] shadow-[0_0_12px_#e5484d]" aria-hidden />
            <span className="text-sm font-bold tracking-widest text-[#f0f3f8]">
              CRIMSON<span className="text-[#e5484d]">_</span>RANGE
            </span>
          </Link>
          <nav className="ml-4 flex items-center gap-4 text-xs">
            <Link to="/challenges" className="text-[#8b98ac] hover:text-[#e5484d] [&.active]:text-[#e5484d]">
              [challenges]
            </Link>
            {me && me.role === "ADMIN" && (
              <Link to="/admin" className="text-[#8b98ac] hover:text-[#e5484d] [&.active]:text-[#e5484d]">
                [admin]
              </Link>
            )}
            {me && me.role !== "STUDENT" && (
              <Link to="/admin/challenges" className="text-[#8b98ac] hover:text-[#e5484d] [&.active]:text-[#e5484d]">
                [cms]
              </Link>
            )}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-xs">
            {me === undefined ? (
              <span className="text-[#5a6a82]">…</span>
            ) : me ? (
              <>
                <span className="text-[#5a6a82]">
                  <span className="text-[#39d353]">●</span> {me.username}
                  <span className="ml-2 rounded border border-[#2a3a4d] px-1 text-[#8b98ac]">{me.role}</span>
                </span>
                <button onClick={doLogout} className="rounded border border-[#2a3a4d] px-2 py-1 text-[#8b98ac] hover:border-[#e5484d] hover:text-[#e5484d]">
                  logout
                </button>
              </>
            ) : (
              <Link to="/login" className="rounded border border-[#2a3a4d] px-2 py-1 text-[#8b98ac] hover:border-[#e5484d] hover:text-[#e5484d]">
                login
              </Link>
            )}
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">{children}</main>
      <footer className="mx-auto max-w-6xl px-4 pb-8 text-[11px] text-[#3d4a5f]">
        <span className="text-[#e5484d]">crimson-range</span> // red-team ctf portal — mvp skeleton, stub range backend
      </footer>
    </div>
  );
}

export const DIFF_STYLE: Record<string, string> = {
  Easy: "border-[#39d353]/50 text-[#39d353]",
  Medium: "border-[#d29922]/60 text-[#d29922]",
  Hard: "border-[#e5484d]/60 text-[#e5484d]",
  Insane: "border-[#bc8cff]/60 text-[#bc8cff]",
};

export const CAT_ICON: Record<string, string> = {
  "AI Red-Team": "◈",
  "Active Directory": "▣",
  "Web/API": "⌁",
  Cloud: "☁",
  "Kill-Chain": "⛓",
};

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`rounded-md border border-[#1d2532] bg-[#0d1117] ${className}`}>{children}</div>;
}
