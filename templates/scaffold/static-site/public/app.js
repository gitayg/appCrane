// Relative path ('api/me', no leading slash) so it works under the app's sub-path.
fetch('api/me')
  .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
  .then(({ user }) => {
    document.getElementById('who').textContent = `Signed in as ${user.name || user.email} (${user.appRole})`;
  })
  .catch((e) => {
    document.getElementById('who').textContent = `Could not load your identity: ${e.message}`;
  });
