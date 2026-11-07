/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#090d16",
        surface: "#0f172a",
        "surface-card": "#131d36",
        "surface-border": "#1e293b",
        cyber: {
          blue: "#38bdf8",
          emerald: "#10b981",
          amber: "#f59e0b",
          orange: "#f97316",
          red: "#ef4444",
          purple: "#a855f7"
        }
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Menlo", "Courier New", "monospace"]
      }
    },
  },
  plugins: [],
}
