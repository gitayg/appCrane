/**
 * Extract the first ```json fenced block from a text body, falling back
 * to the largest {...} substring. Returns null if nothing parseable is
 * found. Used by planner-style callers that prompt Claude for structured
 * output but get prose around it.
 */
export function extractJsonBlock(text) {
  const fenced = text.match(/```json\s*([\s\S]*?)```/);
  const candidate = (fenced ? fenced[1] : text).trim();
  try { return JSON.parse(candidate); } catch (_) {}
  const first = candidate.indexOf('{');
  const last  = candidate.lastIndexOf('}');
  if (first >= 0 && last > first) {
    try { return JSON.parse(candidate.slice(first, last + 1)); } catch (_) {}
  }
  return null;
}
