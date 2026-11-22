// Manifests come from the repository being adopted, so they are untrusted and
// parsed inside the server process. A key that names an object's prototype
// would write onto Object.prototype (or swap an object's prototype) for every
// request the server handles, so such a manifest is refused as unreadable.

export const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export const isReservedKey = (k) => RESERVED_KEYS.has(k);

export const dict = () => Object.create(null);
