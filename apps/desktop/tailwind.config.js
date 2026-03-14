/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/renderer/**/*.{html,js,ts,jsx,tsx}"],
  theme: {
    screens: {
      sm: "600px",
      md: "900px",
      lg: "1024px",
      xl: "1280px",
    },
    extend: {
      colors: {
        brand: {
          blue: "#0057FF",
          "blue-hover": "#004AD9",
          "blue-light": "#EBF0FF",
        },
        surface: {
          bg: "#fafaf9",
          warm: "#f5f4f0",
          card: "#ffffff",
        },
        txt: {
          primary: "#1a1a1a",
          secondary: "#555555",
          muted: "#6b6b6b",
        },
        border: {
          DEFAULT: "#e0e0e0",
          light: "#e8e6e1",
        },
      },
      fontFamily: {
        display: ['"Instrument Serif"', "Georgia", "serif"],
        body: ['"Geist"', "-apple-system", "BlinkMacSystemFont", '"Segoe UI"', "sans-serif"],
        mono: ['"IBM Plex Mono"', '"SF Mono"', '"Fira Code"', "monospace"],
      },
      borderRadius: {
        oc: "4px",
      },
      fontSize: {
        "body-sm": ["0.88rem", { lineHeight: "1.5" }],
        "body-base": ["0.95rem", { lineHeight: "1.6" }],
        "label-sm": ["0.68rem", { lineHeight: "1.4", letterSpacing: "0.08em" }],
        "label-base": ["0.78rem", { lineHeight: "1.4", letterSpacing: "0.08em" }],
      },
    },
  },
  plugins: [],
};
