import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{js,ts,jsx,tsx,mdx}", "./components/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        base: "#0B0D12",
        panel: "#12151C",
        panel2: "#171B24",
        line: "#242938",
        ink: "#E6E9F0",
        dim: "#8A93A6",
        cyan: "#22D3EE",
        amber: "#F5A524",
        rose: "#FB4B67",
        mint: "#2FD583",
      },
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
