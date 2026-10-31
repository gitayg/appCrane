// A coarse "Browser on OS" label for a User-Agent, so a person can recognise a
// remembered device in a list. Deliberately no versions: the label is shown,
// stored and audited, and a full UA string is a fingerprint.
const BROWSERS = [
  [/\bEdg(e|A|iOS)?\//, 'Edge'],
  [/\bOPR\/|\bOpera\b/, 'Opera'],
  [/\bFirefox\/|\bFxiOS\//, 'Firefox'],
  [/\bChrome\/|\bCriOS\//, 'Chrome'],
  [/\bSafari\//, 'Safari'],
];
const SYSTEMS = [
  [/\biPhone|\biPad|\biPod/, 'iOS'],
  [/\bAndroid\b/, 'Android'],
  [/\bWindows\b/, 'Windows'],
  [/\bMac OS X\b|\bMacintosh\b/, 'macOS'],
  [/\bCrOS\b/, 'ChromeOS'],
  [/\bLinux\b/, 'Linux'],
];

export function userAgentFamily(ua) {
  const s = String(ua || '');
  const browser = BROWSERS.find(([re]) => re.test(s))?.[1] || 'Unknown browser';
  const os = SYSTEMS.find(([re]) => re.test(s))?.[1];
  return os ? `${browser} on ${os}` : browser;
}
