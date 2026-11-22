import { useEffect, useState } from 'react';

// API paths are relative ('api/...', no leading slash) so they resolve under
// whatever sub-path AppCrane serves the app at.
async function api(path, init) {
  const res = await fetch(path, { ...init, headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error?.message || `HTTP ${res.status}`);
  return data;
}

const RANK = { none: 0, viewer: 1, user: 2, admin: 3, owner: 4 };

export default function App() {
  const [user, setUser] = useState(null);
  const [notes, setNotes] = useState([]);
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');

  const load = () => api('api/notes').then((d) => setNotes(d.notes)).catch((e) => setError(e.message));

  useEffect(() => {
    api('api/me').then((d) => setUser(d.user)).catch((e) => setError(e.message));
    load();
  }, []);

  const add = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await api('api/notes', { method: 'POST', body: JSON.stringify({ body: draft }) });
      setDraft('');
      load();
    } catch (err) { setError(err.message); }
  };

  const canWrite = user && RANK[user.appRole] >= RANK.user;

  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', maxWidth: 640, margin: '2rem auto', padding: '0 1rem' }}>
      <h1>{document.title}</h1>
      {user && <p>Signed in as {user.name || user.email} ({user.appRole})</p>}
      {error && <p role="alert" style={{ color: '#b00020' }}>{error}</p>}
      {canWrite && (
        <form onSubmit={add}>
          <input value={draft} onChange={(e) => setDraft(e.target.value)} maxLength={2000} placeholder="Write a note" />
          <button type="submit" disabled={!draft.trim()}>Add</button>
        </form>
      )}
      <ul>
        {notes.map((n) => <li key={n.id}>{n.body}</li>)}
      </ul>
    </main>
  );
}
