import React from "react";

const Features = () => {
  return (
    <div>
      <section className="px-4 py-24 md:px-6">
        <div className="mx-auto max-w-5xl">
          <h2 className="mb-4 text-center text-3xl font-bold md:text-4xl">
            How It Works
          </h2>
          <p className="mx-auto mb-16 max-w-xl text-center text-[var(--text-muted)]">
            Three steps to permanent scam protection
          </p>

          <div className="grid gap-8 md:grid-cols-3">
            {[
              {
                step: "01",
                icon: "🔍",
                title: "Paste & Scan",
                desc: "Paste any suspicious message or link. Our AI analyzes it in seconds using a two-layer detection system.",
              },
              {
                step: "02",
                icon: "🤖",
                title: "AI Analysis",
                desc: "Get an instant risk score, category, red flags, and verdict powered by advanced AI models.",
              },
              {
                step: "03",
                icon: "⛓️",
                title: "Store on Blockchain",
                desc: "Confirmed scams are stored permanently on Polygon — tamper-proof, censorship-resistant, forever.",
              },
            ].map(({ step, icon, title, desc }) => (
              <div
                key={step}
                className="glass-panel group rounded-3xl p-6 transition-all hover:-translate-y-1 hover:border-[var(--border-strong)]"
              >
                <div className="mb-4 flex items-center gap-3">
                  <span className="text-3xl">{icon}</span>
                  <span className="mono text-sm font-bold text-[#8fd6ff]">
                    {step}
                  </span>
                </div>
                <h3 className="text-lg font-semibold mb-2">{title}</h3>
                <p className="text-sm leading-relaxed text-[var(--text-muted)]">
                  {desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>
      <section className="px-4 pb-24 pt-8 md:px-6">
        <div className="mx-auto max-w-5xl">
          <h2 className="mb-4 text-center text-3xl font-bold md:text-4xl">
            Built for Everyone
          </h2>
          <p className="mx-auto mb-16 max-w-xl text-center text-[var(--text-muted)]">
            No crypto knowledge required
          </p>

          <div className="grid gap-6 md:grid-cols-2">
            {[
              {
                icon: "🌐",
                title: "Web App",
                desc: "Scan and report from any browser. No installation needed.",
              },
              {
                icon: "🔌",
                title: "Chrome Extension",
                desc: "Auto-warns you before clicking malicious links while browsing.",
              },
              {
                icon: "✈️",
                title: "Telegram Bot",
                desc: "Forward any suspicious message to our bot and get instant analysis.",
              },
              {
                icon: "📊",
                title: "Public Registry",
                desc: "Browse all confirmed scams stored on-chain. Transparent and open.",
              },
            ].map(({ icon, title, desc }) => (
              <div
                key={title}
                className="glass-panel flex items-start gap-4 rounded-2xl p-5 transition-all hover:border-[var(--border-strong)]"
              >
                <div className="text-2xl mt-1">{icon}</div>
                <div>
                  <h3 className="font-semibold mb-1">{title}</h3>
                  <p className="text-sm text-[var(--text-muted)]">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
};

export default Features;
