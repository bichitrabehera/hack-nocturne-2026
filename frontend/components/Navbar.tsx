import Link from "next/link";
import React from "react";

const Navbar = () => {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-[var(--border-soft)] bg-[rgba(3,14,22,0.74)] backdrop-blur-xl">
      <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-4 py-4 md:px-6">
        <div className="flex items-center gap-3">
          <Link href={"/"}>
            <span className="text-lg font-bold tracking-tight text-white md:text-xl">
              Scam<span className="text-[var(--warn)]">Shield</span>
            </span>
          </Link>
        </div>

        <div className="hidden items-center gap-8 text-sm text-[var(--text-muted)] md:flex">
          <a href="/dashboard" className="transition-colors hover:text-white">
            Dashboard
          </a>
          <a href="/sim" className="transition-colors hover:text-white">
            Analytics
          </a>
          <a
            href="https://discord.gg/GqvQPuYp"
            className="rounded-full border border-[var(--border-soft)] bg-[rgba(58,167,255,0.12)] px-4 py-2 font-medium text-[var(--accent-2)] transition-all hover:border-[var(--border-strong)] hover:bg-[rgba(58,167,255,0.2)] hover:text-[#c6e8ff]"
          >
            Join Discord
          </a>
        </div>

        <a
          href="/report"
          className="mono rounded-full border border-[var(--border-strong)] bg-[rgba(255,112,102,0.14)] px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-[#ffc3be] transition-all hover:bg-[rgba(255,112,102,0.26)] md:hidden"
        >
          Report Scam
        </a>
      </div>
    </nav>
  );
};

export default Navbar;
