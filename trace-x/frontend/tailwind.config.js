/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: {
          950: "#070b12",
          900: "#0b1220",
          850: "#0e1726",
          800: "#121c2e",
          700: "#1b2942",
          600: "#27395a",
        },
        accent: {
          DEFAULT: "#22d3ee",
          dim: "#0e7490",
        },
        danger: "#f43f5e",
        warn: "#f59e0b",
        ok: "#10b981",
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
