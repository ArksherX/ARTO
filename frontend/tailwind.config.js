/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "var(--ink)",
        surface: "var(--surface)",
        surface2: "var(--surface-2)",
        raised: "var(--raised)",
        bd: "var(--border)",
        bdsoft: "var(--border-soft)",
        text: "var(--text)",
        muted: "var(--muted)",
        muted2: "var(--muted-2)",
        acc: {
          DEFAULT: "var(--acc)",
          300: "var(--acc-300)",
          500: "var(--acc-500)",
          600: "var(--acc-600)",
          soft: "var(--acc-soft)",
          line: "var(--acc-line)",
        },
        crit: "var(--crit)",
        high: "var(--high)",
        med: "var(--med)",
        low: "var(--low)",
        ok: "var(--ok)",
      },
      fontFamily: {
        display: ["Archivo", "IBM Plex Sans", "system-ui", "sans-serif"],
        body: ["IBM Plex Sans", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      borderRadius: { xl2: "16px" },
    },
  },
  plugins: [],
};
