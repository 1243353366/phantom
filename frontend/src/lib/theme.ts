/**
 * Cytoscape needs literal colours; it does not resolve CSS variables. So the
 * palette is read from the stylesheet once per render, which keeps the graph in
 * step with the app's light/dark state instead of hard-coding a colour and
 * having it disappear in the other theme.
 */
export interface Palette {
  ink: string;
  inkMuted: string;
  surface2: string;
  line: string;
  lineStrong: string;
  accent: string;
  accentSoft: string;
}

const FALLBACK: Palette = {
  ink: "#1c1a17",
  inkMuted: "#6b655d",
  surface2: "#efece7",
  line: "#ddd8d0",
  lineStrong: "#b8b0a5",
  accent: "#8a5a2b",
  accentSoft: "#e8dccd",
};

export function palette(): Palette {
  if (typeof window === "undefined") return FALLBACK;
  const computed = getComputedStyle(document.documentElement);
  const read = (name: string, fallback: string) =>
    computed.getPropertyValue(name).trim() || fallback;
  return {
    ink: read("--ink", FALLBACK.ink),
    inkMuted: read("--ink-muted", FALLBACK.inkMuted),
    surface2: read("--surface-2", FALLBACK.surface2),
    line: read("--line", FALLBACK.line),
    lineStrong: read("--line-strong", FALLBACK.lineStrong),
    accent: read("--accent", FALLBACK.accent),
    accentSoft: read("--accent-soft", FALLBACK.accentSoft),
  };
}
