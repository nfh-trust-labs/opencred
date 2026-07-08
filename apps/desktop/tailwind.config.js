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
        // Semantic state colors — replace raw green/amber/red palette usage.
        // `*-bg` are the tint backgrounds, `*-border` the hairline borders.
        state: {
          success: "#15803d",
          "success-bg": "#f0fdf4",
          "success-border": "#bbf7d0",
          warning: "#b45309",
          "warning-bg": "#fffbeb",
          "warning-border": "#fde68a",
          danger: "#b91c1c",
          "danger-bg": "#fef2f2",
          "danger-border": "#fecaca",
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
        // Body scale (no built-in tracking). `body-2xs` is the small-text
        // floor — replaces the sub-0.72rem arbitrary sizes that were too small.
        "body-2xs": ["0.72rem", { lineHeight: "1.45" }],
        "body-xs": ["0.8rem", { lineHeight: "1.5" }],
        "body-sm": ["0.88rem", { lineHeight: "1.5" }],
        "body-base": ["0.95rem", { lineHeight: "1.6" }],
        // Label scale — mono/uppercase eyebrows, carries letter-spacing.
        "label-sm": ["0.68rem", { lineHeight: "1.4", letterSpacing: "0.08em" }],
        "label-base": ["0.78rem", { lineHeight: "1.4", letterSpacing: "0.08em" }],
      },
    },
  },
  plugins: [],
};
