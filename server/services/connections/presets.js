// Provider presets: the upstream and auth shape each provider uses, so a
// platform admin registering GitHub or Slack supplies only the credential.
// 'generic' is any HTTPS API with a bearer token, a named header or basic auth.

export const AUTH_TYPES = ['bearer', 'header', 'basic', 'google_service_account'];

export const PRESETS = Object.freeze({
  generic: { base_url: undefined, auth_type: 'bearer', auth_types: ['bearer', 'header', 'basic'], headers: {} },
  github: {
    base_url: 'https://api.github.com',
    auth_type: 'bearer',
    auth_types: ['bearer'],
    headers: { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
  },
  slack: { base_url: 'https://slack.com/api', auth_type: 'bearer', auth_types: ['bearer'], headers: {} },
  google: {
    base_url: 'https://www.googleapis.com',
    auth_type: 'google_service_account',
    auth_types: ['google_service_account'],
    headers: {},
    checkBaseUrl(url, bad) {
      if (!/^https:\/\/([a-z0-9-]+\.)*googleapis\.com(:[0-9]+)?(\/|$)/.test(url)) throw bad('a google connection points at a *.googleapis.com address');
    },
  },
  // Jira and Confluence Cloud: https://<site>.atlassian.net, an account e-mail and an API token.
  atlassian: {
    base_url: undefined,
    auth_type: 'basic',
    auth_types: ['basic', 'bearer'],
    headers: { accept: 'application/json' },
    checkBaseUrl(url, bad) {
      if (!/^https:\/\/[a-z0-9-]+\.atlassian\.net(:[0-9]+)?(\/|$)/.test(url)) throw bad('an atlassian connection points at https://<site>.atlassian.net');
    },
  },
});

export const PROVIDERS = Object.keys(PRESETS);
