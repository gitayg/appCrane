import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// The survey card sits over a running app. It must never take keyboard focus
// from it (the v2.107.7 lesson: a stolen focus swallows what the person types,
// with no error anywhere), must not animate for reduced-motion users, and must
// be mounted wherever the app top bar is.

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const card = read('studio-web/src/components/runtime-topbar/SurveyCard.tsx');

test('the survey card never takes focus', () => {
  assert.doesNotMatch(card, /\.focus\(/, 'the card calls .focus() -- it would take the keyboard from the app');
  assert.doesNotMatch(card, /autoFocus/, 'autoFocus takes the keyboard from the app on mount');
  assert.doesNotMatch(card, /aria-modal|role="dialog"/, 'the card is not a modal: the app stays usable around it');
  assert.match(card, /role="region"/);
});

test('the card animates only without a reduced-motion preference', () => {
  assert.match(card, /@media \(prefers-reduced-motion: no-preference\) \{\s*\.crane-survey \{ animation:/);
  assert.equal(card.match(/animation:/g).length, 1, 'an animation outside the reduced-motion guard');
});

test('the card asks for the pending survey of its app and snoozes on "Not now"', () => {
  assert.match(card, /\/api\/surveys\/pending\?app=\$\{encodeURIComponent\(slug\)\}/);
  assert.match(card, /\/api\/surveys\/\$\{survey!\.id\}\/snooze/);
  assert.match(card, /\/api\/surveys\/\$\{survey\.id\}\/responses/);
});

test('every top bar host mounts the card', () => {
  assert.match(read('studio-web/src/pages/AppFrame.tsx'), /<SurveyCard slug=\{stage\.slug\}/);
  assert.match(read('studio-web/src/pages/Applications.tsx'), /<SurveyCard slug=\{frame\.slug\}/);
  const panels = read('studio-web/src/topbar-element/CranePanels.tsx');
  assert.match(panels, /customElements\.define\('crane-survey-card',\s+CraneSurveyCard\)/);
  const portal = read('docs/login.html');
  assert.match(portal, /<crane-survey-card id="surveyCard"><\/crane-survey-card>/);
  assert.match(portal, /sc\.setAttribute\('slug', slug\)/);
  assert.match(portal, /getElementById\('surveyCard'\)\?\.removeAttribute\('slug'\)/, 'closing the app leaves the card up');
});

test('the admin preview shows the draft in the real card and sends nothing', () => {
  // Preview returns before the pending fetch, the snooze and the response POST,
  // so trying a survey out never snoozes it or stores (and e-mails) an answer.
  const at = (re) => card.search(re);
  const before = (guard, call, msg) => {
    const g = at(guard), c = at(call);
    assert.ok(c >= 0, `control: ${call} not found`);
    assert.ok(g >= 0 && g < c, msg);
  };
  before(/if \(preview\) \{ setSurvey\(preview\); setPhase\('open'\); return \}/,
    /adminApi\.get<[^>]*>\(`\/api\/surveys\/pending/, 'preview must return before the pending fetch');
  before(/if \(preview\) \{ onClose\?\.\(\); return \}/, /adminApi\.post\(`\/api\/surveys\/\$\{survey!\.id\}\/snooze/, 'preview "Not now" must not snooze');
  before(/if \(preview\) \{ setPhase\('thanks'\); return \}/, /adminApi\.post\(`\/api\/surveys\/\$\{survey\.id\}\/responses/, 'preview "Send" must not post an answer');
  const admin = read('studio-web/src/components/surveys/SurveyAdmin.tsx');
  assert.match(admin, /<SurveyCard slug=\{null\} preview=\{preview\} onClose=\{closePreview\} \/>/);
  assert.match(admin, />Preview<\/button>/);
  assert.match(admin, /replaceAll\('\{app\}', appName\)/, 'the preview shows {app} as an app name, as the server does');
});
