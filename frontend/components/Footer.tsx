import Link from "next/link";
import React from "react";

const Footer = () => {
  return (
    <footer className="mt-auto border-t border-[var(--border-soft)] bg-[rgba(2,10,16,0.6)] px-4 pb-10 pt-20 md:px-6">
      <div className="mx-auto max-w-6xl">
        <div className="mb-16 text-center">
          <h2 className="select-none bg-gradient-to-r from-[#5f7d95] via-[#7dc3ff] to-[#5f7d95] bg-clip-text text-6xl font-black tracking-tighter text-transparent md:text-8xl">
            SCAMSHIELD
          </h2>
          <p className="mt-4 text-lg text-[var(--text-muted)]">
            Community-driven. AI-powered. Blockchain-secured.
          </p>
        </div>

        <div className="mb-10 flex flex-wrap justify-center gap-8 text-sm text-[var(--text-muted)]">
          <Link href="/" className="transition-colors hover:text-white">
            Home
          </Link>
          <Link href="/dashboard" className="transition-colors hover:text-white">
            Dashboard
          </Link>
          <Link href="/sim" className="transition-colors hover:text-white">
            Analytics
          </Link>
          <Link href="/result" className="transition-colors hover:text-white">
            Registry
          </Link>
          <Link href="/report" className="transition-colors hover:text-white">
            Report Scam
          </Link>
        </div>

        <div className="flex flex-col items-center justify-between gap-4 border-t border-[var(--border-soft)] pt-8 text-sm text-[#6f879a] md:flex-row">
          <p>© 2026 ScamShield. Built at Hack-Nocturne 2026.</p>
          <p className="flex items-center gap-2">
            Powered by
            <span className="font-medium text-[#8cd8ff]">Polygon</span>+
            <span className="font-medium text-[#7de1cf]">OpenAI</span>
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
