import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { Shell, Card } from "~/components/shell";
import { login } from "~/server/functions";

export const Route = createFileRoute("/login")({
  component: Login,
});

function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await login({ data: { username, password } });
      if (r.ok) {
        navigate({ to: "/challenges" });
      } else {
        setError(r.error ?? "Login failed.");
      }
    } catch {
      setError("Login failed — server unreachable.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Shell>
      <div className="mx-auto max-w-md">
        <Card className="p-6">
          <p className="text-xs text-[#39d353]">$ auth --portal</p>
          <h1 className="mt-2 text-xl font-bold text-[#f0f3f8]">operator login</h1>
          <form onSubmit={submit} className="mt-4 space-y-3 text-xs">
            <label className="block">
              <span className="text-[#5a6a82]">username</span>
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                className="mt-1 w-full rounded border border-[#2a3a4d] bg-black/60 px-3 py-2 text-[#c9d4e3] outline-none focus:border-[#e5484d]"
              />
            </label>
            <label className="block">
              <span className="text-[#5a6a82]">password</span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                className="mt-1 w-full rounded border border-[#2a3a4d] bg-black/60 px-3 py-2 text-[#c9d4e3] outline-none focus:border-[#e5484d]"
              />
            </label>
            {error && <p className="text-[#e5484d]">[!] {error}</p>}
            <button
              type="submit"
              disabled={busy}
              className="w-full rounded border border-[#e5484d] bg-[#e5484d]/10 px-3 py-2 font-bold text-[#ff7b72] hover:bg-[#e5484d]/20 disabled:opacity-50"
            >
              {busy ? "authenticating…" : "> authenticate"}
            </button>
          </form>
          <div className="mt-4 rounded border border-dashed border-[#2a3a4d] p-3 text-[11px] leading-5 text-[#5a6a82]">
            <p className="text-[#8b98ac]">// seeded demo logins (mvp only)</p>
            <p>student — <span className="text-[#c9d4e3]">neo / crimson-neo</span></p>
            <p>student — <span className="text-[#c9d4e3]">trinity / crimson-trinity</span></p>
            <p>admin — <span className="text-[#c9d4e3]">admin / crimson-admin</span></p>
          </div>
        </Card>
      </div>
    </Shell>
  );
}
