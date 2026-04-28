// LandingPage.tsx
import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";

const AnimatedCounter: React.FC<{ target: number; duration?: number; suffix?: string }> = ({
  target,
  duration = 2000,
  suffix = "",
}) => {
  const [count, setCount] = useState(0);

  useEffect(() => {
    let start = 0;
    const increment = target / (duration / 16);
    const interval = setInterval(() => {
      start += increment;
      if (start >= target) {
        setCount(target);
        clearInterval(interval);
      } else {
        setCount(Math.floor(start));
      }
    }, 16);
    return () => clearInterval(interval);
  }, [target, duration]);

  return (
    <span>
      {count}
      {suffix}
    </span>
  );
};

const LandingPage: React.FC = () => {
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      setMousePos({ x: e.clientX, y: e.clientY });
    };
    window.addEventListener("mousemove", handleMouseMove);
    return () => window.removeEventListener("mousemove", handleMouseMove);
  }, []);

  return (
    <div className="relative bg-void text-text-primary overflow-x-hidden">
      {/* Enhanced animated background */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        {/* Gradient orbs that follow mouse */}
        <div
          className="absolute w-96 h-96 rounded-full blur-3xl opacity-20 transition-all duration-300 ease-out"
          style={{
            background: "radial-gradient(circle, #00d4ff, transparent)",
            left: `${mousePos.x - 192}px`,
            top: `${mousePos.y - 192}px`,
          }}
        />
        <div className="absolute top-20 right-10 w-80 h-80 rounded-full bg-gradient-to-r from-accent/20 to-cyan-500/10 blur-3xl opacity-30 animate-pulse" />
        <div className="absolute bottom-40 left-20 w-72 h-72 rounded-full bg-gradient-to-r from-danger/10 to-orange-500/10 blur-3xl opacity-20" />

        {/* Animated grid background */}
        <div className="absolute inset-0 bg-[linear-gradient(rgba(0,212,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,212,255,0.03)_1px,transparent_1px)] bg-[length:50px_50px] opacity-30" />
      </div>

      <div className="relative z-10">
        {/* Hero Section */}
        <div className="min-h-screen flex items-center">
          <div className="mx-auto max-w-7xl px-6 py-12 w-full">
            <div className="flex flex-col gap-12 lg:flex-row lg:items-center lg:justify-between">
              {/* Hero Content */}
              <div className="max-w-3xl">
                <div className="inline-flex items-center gap-3 rounded-full border border-accent/30 bg-accent/10 px-4 py-2 text-xs font-mono text-accent backdrop-blur-md mb-8 hover:border-accent/60 transition-all cursor-default group">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-accent"></span>
                  </span>
                  <span className="group-hover:translate-x-1 transition-transform">ThreatWeaver v2.4 · Enterprise Security Platform</span>
                </div>

                <h1 className="text-5xl md:text-6xl lg:text-7xl font-display font-bold tracking-tighter text-white leading-tight mb-6">
                  Predict attack paths{" "}
                  <span className="relative">
                    <span className="relative z-10 bg-gradient-to-r from-accent via-cyan-300 to-blue-400 bg-clip-text text-transparent animate-pulse">
                      before they happen
                    </span>
                    <span className="absolute inset-0 bg-gradient-to-r from-accent via-cyan-300 to-blue-400 blur-xl opacity-30 -z-10" />
                  </span>
                </h1>

                <p className="mt-8 text-lg text-text-secondary leading-relaxed max-w-2xl">
                  Combine live network topology scans, AI-powered attack path prediction, and automated
                  remediation guidance. Identify and fix exposure{" "}
                  <span className="text-accent font-semibold">before attackers do</span>.
                </p>

                {/* CTA Buttons */}
                <div className="mt-10 flex flex-wrap gap-4 items-center">
                  <Link
                    to="/login"
                    className="group relative rounded-2xl bg-accent px-8 py-4 text-sm font-semibold text-void transition-all hover:shadow-2xl hover:shadow-accent/40 hover:scale-105 active:scale-95 overflow-hidden"
                  >
                    <span className="absolute inset-0 bg-gradient-to-r from-accent/80 to-accent opacity-0 group-hover:opacity-100 transition-opacity" />
                    <span className="relative flex items-center gap-2">
                      Launch Dashboard <span className="group-hover:translate-x-1 transition-transform">→</span>
                    </span>
                  </Link>
                  <Link
                    to="/register"
                    className="rounded-2xl border-2 border-accent/50 bg-void px-8 py-4 text-sm font-semibold text-text-primary transition-all hover:border-accent hover:bg-accent/5 hover:shadow-lg hover:shadow-accent/20 active:scale-95"
                  >
                    Create Free Account
                  </Link>
                </div>

                {/* Trust badges */}
                <div className="mt-12 flex items-center gap-6 text-sm text-text-secondary">
                  <div className="flex items-center gap-2">
                    <span className="text-accent">✓</span> No credit card required
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-accent">✓</span> 2-minute setup
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-accent">✓</span> Live data included
                  </div>
                </div>
              </div>

              {/* Animated demo card */}
              <div className="relative group hidden lg:block">
                <div className="absolute -inset-1 rounded-3xl bg-gradient-to-r from-accent/30 to-cyan-500/20 blur-2xl opacity-50 group-hover:opacity-100 transition-all duration-500" />
                <div className="absolute -inset-0.5 rounded-3xl bg-gradient-to-br from-accent/10 to-transparent opacity-0 group-hover:opacity-100 transition-all" />

                <div className="relative rounded-3xl border border-accent/30 bg-surface/80 backdrop-blur-xl p-8 shadow-2xl group-hover:border-accent/60 transition-all">
                  <div className="absolute top-4 right-4 flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-danger/60" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
                    <div className="w-3 h-3 rounded-full bg-green-500/60" />
                  </div>

                  <p className="text-xs font-mono text-accent uppercase tracking-widest">Live Analysis</p>

                  <div className="mt-6 space-y-4">
                    <div>
                      <div className="flex justify-between items-baseline mb-2">
                        <span className="text-sm text-text-secondary">Critical Paths Detected</span>
                        <span className="text-2xl font-bold text-accent">
                          <AnimatedCounter target={3} />
                        </span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-panel overflow-hidden">
                        <div className="h-full w-1/3 rounded-full bg-gradient-to-r from-accent to-cyan-400 animate-pulse" />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between items-baseline mb-2">
                        <span className="text-sm text-text-secondary">Network Nodes</span>
                        <span className="text-2xl font-bold text-cyan-300">
                          <AnimatedCounter target={47} />
                        </span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-panel overflow-hidden">
                        <div className="h-full w-2/3 rounded-full bg-gradient-to-r from-cyan-400 to-blue-400" />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between items-baseline mb-2">
                        <span className="text-sm text-text-secondary">GNRI Score</span>
                        <span className="text-2xl font-bold text-accent">
                          <AnimatedCounter target={76} suffix="/100" />
                        </span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-panel overflow-hidden">
                        <div className="h-full w-3/4 rounded-full bg-gradient-to-r from-yellow-400 to-danger" />
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 pt-6 border-t border-border/50 text-xs text-text-dim">
                    Last update: just now • Auto-refresh: enabled
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Features Section */}
        <div className="py-24 px-6">
          <div className="mx-auto max-w-7xl">
            <div className="text-center mb-16">
              <h2 className="text-4xl md:text-5xl font-display font-bold text-white mb-4">
                Purpose-built for security teams
              </h2>
              <p className="text-lg text-text-secondary max-w-2xl mx-auto">
                Streamline your attack surface analysis with intelligent automation
              </p>
            </div>

            <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
              {[
                {
                  icon: "⬡",
                  title: "Live Topology Scanning",
                  description: "Map your entire network in minutes with AI-powered asset discovery and risk classification.",
                  color: "cyan",
                },
                {
                  icon: "↯",
                  title: "Attack Path Prediction",
                  description: "Visualize how attackers could traverse your network and identify the most dangerous routes.",
                  color: "danger",
                },
                {
                  icon: "⚕",
                  title: "AI Remediation Planning",
                  description: "Generate actionable remediation steps ranked by impact and exploitability.",
                  color: "green",
                },
                {
                  icon: "R",
                  title: "Role-based Access",
                  description: "Secure analyst and admin workflows with JWT auth and clear role boundaries.",
                  color: "blue",
                },
                {
                  icon: "E",
                  title: "Executive Reporting",
                  description: "Track risk trends and remediation velocity with export-ready leadership summaries.",
                  color: "purple",
                },
                {
                  icon: "24/7",
                  title: "Continuous Monitoring",
                  description: "Keep scans and path analysis running so new exposure is surfaced quickly.",
                  color: "orange",
                },
              ].map((feature, idx) => (
                <div
                  key={feature.title}
                  className="group relative rounded-2xl border border-border bg-surface/40 p-6 backdrop-blur-sm transition-all duration-300 hover:border-accent/50 hover:bg-surface/60 hover:shadow-lg hover:shadow-accent/10 hover:translate-y-[-4px]"
                  style={{ animationDelay: `${idx * 100}ms` }}
                >
                  <div className="absolute top-0 right-0 w-20 h-20 rounded-2xl bg-gradient-to-br from-accent/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                  <div className="relative z-10">
                    <span className="text-4xl group-hover:scale-110 transition-transform inline-block">{feature.icon}</span>
                    <h3 className="mt-4 text-xl font-semibold text-white">{feature.title}</h3>
                    <p className="mt-2 text-sm text-text-secondary leading-relaxed">{feature.description}</p>
                    <div className="mt-4 h-1 w-12 bg-gradient-to-r from-accent to-cyan-400 rounded-full opacity-0 group-hover:opacity-100 transition-opacity" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* How It Works */}
        <div className="py-24 px-6">
          <div className="mx-auto max-w-7xl">
            <div className="mb-14 text-center">
              <p className="text-sm font-mono text-accent uppercase tracking-[0.28em] mb-4">How it works</p>
              <h2 className="text-4xl md:text-5xl font-display font-bold text-white mb-4">
                From scan to remediation in one flow
              </h2>
              <p className="text-lg text-text-secondary max-w-3xl mx-auto">
                ThreatWeaver continuously maps assets, predicts attacker movement, and prioritizes fixes so your team
                can act fast without context switching.
              </p>
            </div>

            <div className="grid gap-6 lg:grid-cols-3">
              {[
                {
                  step: "Step 1",
                  title: "Discover Assets",
                  description:
                    "Run continuous network discovery to keep topology, exposed ports, and weak points up to date.",
                },
                {
                  step: "Step 2",
                  title: "Model Attack Paths",
                  description:
                    "Graph relationships between hosts and services, then identify high-risk traversal paths automatically.",
                },
                {
                  step: "Step 3",
                  title: "Prioritize Fixes",
                  description:
                    "Generate remediation plans ranked by exploitability, blast radius, and business impact.",
                },
              ].map((item) => (
                <div
                  key={item.title}
                  className="rounded-2xl border border-border bg-surface/40 p-6 backdrop-blur-sm transition-all duration-300 hover:border-accent/50 hover:bg-surface/60"
                >
                  <p className="text-xs font-mono uppercase tracking-[0.2em] text-accent/90">{item.step}</p>
                  <h3 className="mt-4 text-2xl font-semibold text-white">{item.title}</h3>
                  <p className="mt-3 text-sm leading-relaxed text-text-secondary">{item.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Stats Section */}
        <div className="py-20 px-6 bg-gradient-to-r from-accent/5 via-transparent to-cyan-500/5">
          <div className="mx-auto max-w-7xl">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
              {[
                { label: "Security Teams", value: 500 },
                { label: "Networks Analyzed", value: 2800 },
                { label: "Attack Paths Prevented", value: 15000 },
                { label: "Uptime", value: 99, suffix: "%" },
              ].map((stat) => (
                <div key={stat.label} className="text-center">
                  <div className="text-3xl md:text-4xl font-bold text-accent mb-2">
                    <AnimatedCounter target={stat.value} suffix={stat.suffix || ""} />
                  </div>
                  <p className="text-sm text-text-secondary">{stat.label}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Why ThreatWeaver Section */}
        <div className="py-24 px-6">
          <div className="mx-auto max-w-7xl">
            <div className="rounded-3xl border border-accent/20 bg-gradient-to-br from-surface/60 to-surface/30 backdrop-blur-md p-8 lg:p-16">
              <div className="grid gap-12 lg:grid-cols-2 lg:gap-16 items-center">
                <div>
                  <p className="text-sm font-mono text-accent uppercase tracking-wider mb-4">Why choose us</p>
                  <h2 className="text-3xl lg:text-4xl font-display font-bold text-white mb-6">
                    Reduce network risk faster than ever before
                  </h2>
                  <p className="text-base text-text-secondary leading-relaxed mb-8">
                    Modern security requires seeing your entire attack surface at once. ThreatWeaver
                    brings your team together around a single source of truth for network risk.
                  </p>
                </div>

                <div className="space-y-4">
                  {[
                    { icon: "⬡", title: "Unified Dashboard", desc: "All analysis, paths, and remediation in one place" },
                    { icon: "🔐", title: "Enterprise Auth", desc: "JWT tokens, role-based access control, audit logs" },
                    { icon: "⚡", title: "Real-time Scanning", desc: "Live nmap integration with continuous monitoring" },
                    { icon: "🤖", title: "AI-Powered", desc: "LLM-driven remediation with rule-based fallback" },
                  ].map((item) => (
                    <div
                      key={item.title}
                      className="rounded-xl border border-border bg-void/50 p-4 hover:border-accent/50 transition-all hover:bg-accent/5 cursor-default group"
                    >
                      <p className="flex items-center gap-3 font-semibold text-white mb-1">
                        <span className="text-xl group-hover:scale-125 transition-transform">{item.icon}</span>
                        {item.title}
                      </p>
                      <p className="text-sm text-text-secondary ml-9">{item.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Final CTA Section */}
        <div className="py-24 px-6">
          <div className="mx-auto max-w-4xl">
            <div className="relative rounded-3xl border border-accent/30 bg-gradient-to-r from-accent/10 via-accent/5 to-cyan-500/5 p-8 lg:p-16 text-center overflow-hidden group">
              <div className="absolute inset-0 bg-gradient-to-r from-accent/0 via-accent/10 to-accent/0 opacity-0 group-hover:opacity-100 transition-opacity" />

              <div className="relative z-10">
                <h2 className="text-3xl lg:text-4xl font-display font-bold text-white mb-4">
                  Ready to secure your network?
                </h2>
                <p className="text-lg text-text-secondary mb-8 max-w-2xl mx-auto">
                  Join security teams that have reduced their network risk by up to 60% using ThreatWeaver.
                  Start your free trial today.
                </p>

                <div className="flex flex-col sm:flex-row gap-4 justify-center">
                  <Link
                    to="/register"
                    className="group relative rounded-2xl bg-accent px-8 py-4 text-sm font-semibold text-void transition-all hover:shadow-2xl hover:shadow-accent/40 hover:scale-105 active:scale-95"
                  >
                    <span className="relative flex items-center justify-center gap-2">
                      Start Free Trial <span className="group-hover:translate-x-1 transition-transform">→</span>
                    </span>
                  </Link>
                  <Link
                    to="/login"
                    className="rounded-2xl border-2 border-accent/50 bg-void px-8 py-4 text-sm font-semibold text-text-primary transition-all hover:border-accent hover:bg-accent/5"
                  >
                    Sign In
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <footer className="py-12 px-6 border-t border-border/50 text-center text-sm text-text-dim">
          <div className="mx-auto max-w-7xl">
            <p className="mb-4">© 2026 ThreatWeaver — Enterprise-grade attack path analysis platform.</p>
            <p className="text-xs">Secure your network. Reduce risk. Stay ahead of threats.</p>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default LandingPage;
