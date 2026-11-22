// The text tests work-review applies to a typed prompt. They decide which
// prompts count as vague, which carry done-criteria, which are corrections and
// which are bare nudges, and so drive the "vague prompts" and "rework" findings.
// No side effects: the analyzer and the tests both import this file.
//
// test/fixtures/work-review-labelled-prompts.json holds prompts labelled by a
// person, by meaning; test/work-review-classify.test.js scores these tests
// against them (precision and recall) and fails if a change makes any score
// drop below the floor recorded there. Change a pattern, run that test, and the
// table it prints shows what the change won and lost.

// A bare "stop" redirects; "stop the dev server when you finish" is an instruction,
// and so is "don't forget ...". A soft opener ("hmm,", "ok,") may come first, and
// "ok but ..." / "yes but ..." is a redirect whatever follows.
export const CORRECTION_RE = /^(?:(?:hmm+|ok(?:ay)?|yes|sure)[,.]?\s+)?(?:no[,.! ]|nope|don'?t(?! forget)|do not|stop(?:[,.!]|$| it\b| that\b| doing\b)|wrong|actually|instead|that'?s (?:not|wrong)|not (?:what i|like that|that)|i said|i told you|why did you|you (?:forgot|missed|broke)|please don'?t|never |undo\b|revert\b|roll ?back\b|that (?:approach )?won'?t work)|^(?:ok(?:ay)?|yes|sure)[,.]?\s+but\b/i;
// Concrete anchors in a prompt: a path or file name, code in backticks, an identifier,
// an error/line reference, an HTTP route, a URL. A prompt with none of them makes
// Claude go find out. The bare word "error" is not an anchor: "improve the error
// handling" names nothing Claude can go to.
// Case-sensitive on purpose: `camelCase` must not match every lowercase word.
export const ANCHOR_RE = /(`[^`]+`|\b[\w-]+\.(?:js|mjs|ts|tsx|jsx|py|go|rs|java|rb|php|css|html|json|ya?ml|md|sql|sh|toml)\b|(?:^|\s)\.{0,2}\/[\w.-]+\/|https?:\/\/|\b[a-z]+[A-Z]\w*\b|\b\w+\(\)|\b(?:[A-Z]\w*(?:Error|Exception)\b|Error:|Traceback|line \d+|status \d{3})|\b(?:GET|POST|PUT|PATCH|DELETE) \/\S*)/;
// Done-criteria: tells Claude when to stop and how to check.
export const CRITERIA_RE = /\b(should|must|expect(?:ed)?|so that|done when|until|make sure|verify|pass(?:es)?|returns?|instead of|acceptance|has to|check (?:that|the)|when you'?re done)\b/i;
// One or more go-aheads and nothing else: "sure, go", "lgtm, proceed".
export const NUDGE_RE = /^(?:(?:continue|go on|go ahead|go|proceed|yes|yep|y|ok(?:ay)?|sure|lgtm|do it|next|keep going|carry on)[,.!\s]*)+$/i;
// Longer than this and a prompt is not called vague even with no anchor: it
// usually explains enough in words.
export const VAGUE_MAX_CHARS = 300;

export const isCorrection = t => CORRECTION_RE.test(String(t).trim());
export const isNudge = t => NUDGE_RE.test(String(t).trim());
export const isAnchored = t => ANCHOR_RE.test(String(t));
export const hasCriteria = t => CRITERIA_RE.test(String(t));
// What the "vague prompts" finding counts: a request, not a nudge, with no
// concrete anchor, short enough that words alone are unlikely to place it.
export const isVague = t => !isNudge(t) && !isAnchored(t) && String(t).length < VAGUE_MAX_CHARS;
