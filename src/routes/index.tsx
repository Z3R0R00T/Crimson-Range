import { createFileRoute, Link } from "@tanstack/react-router";
import { Shell } from "~/components/shell";

export const Route = createFileRoute("/")({
  component: Home,
});

function Home() {
  return (
    <Shell>
      <section className="rounded-md border border-[#1d2532] bg-[#0d1117] p-8 md:p-12">
        <p className="text-xs text-[#39d353]">$ ./crimson-range --init</p>
        <h1 className="mt-3 text-3xl font-bold tracking-tight text-[#f0f3f8] md:text-5xl">
          CRIMSON<span className="text-[#e5484d]">_</span>RANGE
        </h1>
        <p className="mt-2 text-sm text-[#8b98ac]">
          Red-team CTF portal — AI, AD, web/API, cloud &amp; kill-chain labs.
        </p>
        <pre className="mt-6 overflow-x-auto rounded border border-[#1d2532] bg-black/60 p-4 text-xs leading-6 text-[#c9d4e3]">
{`root@range:~# list-labs --all
[+] payroll-whisperer      [AI Red-Team]      500 pts
[+] helpdesk-harvest       [Active Directory] 700 pts
[+] invoice-inspector      [Web/API]          350 pts
root@range:~# connect --portal
> establishing secure channel... OK`}
        </pre>
        <div className="mt-6 flex flex-wrap gap-3 text-xs">
          <Link
            to="/challenges"
            className="rounded border border-[#e5484d] bg-[#e5484d]/10 px-4 py-2 font-bold text-[#ff7b72] hover:bg-[#e5484d]/20"
          >
            &gt; enter the range
          </Link>
          <Link to="/login" className="rounded border border-[#2a3a4d] px-4 py-2 text-[#8b98ac] hover:border-[#39d353] hover:text-[#39d353]">
            &gt; operator login
          </Link>
        </div>
        <div className="mt-8 grid gap-3 text-xs md:grid-cols-3">
          {[
            ["◈ AI RED-TEAM", "Prompt-injection, tool abuse, model exfiltration labs."],
            ["▣ ACTIVE DIRECTORY", "Kerberos abuse, delegation traps, full kill-chains."],
            ["⌁ WEB / API", "BOLA, IDOR, auth bypasses against modern stacks."],
          ].map(([t, d]) => (
            <div key={t} className="rounded border border-[#1d2532] bg-black/40 p-3">
              <p className="font-bold text-[#f0f3f8]">{t}</p>
              <p className="mt-1 text-[#5a6a82]">{d}</p>
            </div>
          ))}
        </div>
      </section>
    </Shell>
  );
}
