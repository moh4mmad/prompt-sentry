export const ACTION_COLORS: Record<string, string> = {
  allow:    "#00ffa3",
  monitor:  "#00b0ff",
  sanitize: "#ffc107",
  block:    "#ff6d00",
  alert:    "#ff1744",
};

export const SEVERITY_COLORS: Record<string, string> = {
  low:      "#00ffa3",
  medium:   "#ffc107",
  high:     "#ff6d00",
  critical: "#ff1744",
};

export const ATTACK_PALETTE = [
  "#00ffa3", "#00b0ff", "#d050ff", "#ffc107",
  "#ff6d00", "#ff1744", "#00e5cc", "#e040fb",
  "#ffd740", "#40c4ff", "#69f0ae", "#ff5252",
];

export function riskColor(score: number): string {
  if (score >= 0.9)  return "#ff1744";
  if (score >= 0.75) return "#ff6d00";
  if (score >= 0.5)  return "#ffc107";
  if (score >= 0.25) return "#00b0ff";
  return "#00ffa3";
}
