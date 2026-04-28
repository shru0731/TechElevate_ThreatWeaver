/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        display: ["'Syne'", "sans-serif"],
        mono: ["'JetBrains Mono'", "monospace"],
        body: ["'DM Sans'", "sans-serif"],
      },
      colors: {
        void: "#080c14",
        surface: "#0d1421",
        panel: "#111827",
        border: "#1e2d3d",
        accent: "#00d4ff",
        danger: "#ff2d55",
        warn: "#ff9f0a",
        safe: "#30d158",
        mid: "#ffd60a",
        muted: "#5f7aa0",
        text: {
          primary: "#f4faff",
          secondary: "#c8d8f0",
          dim: "#9ab3d0",
        },
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan": "scan 2s linear infinite",
        "glow": "glow 2s ease-in-out infinite alternate",
        "slide-in": "slideIn 0.3s ease-out",
        "fade-up": "fadeUp 0.4s ease-out",
      },
      keyframes: {
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        glow: {
          "0%": { boxShadow: "0 0 5px #00d4ff40" },
          "100%": { boxShadow: "0 0 20px #00d4ff80, 0 0 40px #00d4ff20" },
        },
        slideIn: {
          "0%": { transform: "translateX(-10px)", opacity: 0 },
          "100%": { transform: "translateX(0)", opacity: 1 },
        },
        fadeUp: {
          "0%": { transform: "translateY(8px)", opacity: 0 },
          "100%": { transform: "translateY(0)", opacity: 1 },
        },
      },
      backgroundImage: {
        "grid-pattern":
          "linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px)",
      },
      backgroundSize: {
        grid: "40px 40px",
      },
    },
  },
  plugins: [],
};
