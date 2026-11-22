import { Modal } from './Modal'
import { fmtDuration, fmtNum } from './format'
import type { Release } from './releaseApi'

type Row = { label: string; get: (r: Release) => number | null | undefined; digits?: number; higherIsBetter?: boolean; fmt?: (n: number | null | undefined) => string }

const ROWS: Row[] = [
  { label: 'Requests per day', get: r => r.metrics?.requests_per_day, digits: 1, higherIsBetter: true },
  { label: 'Active users per day', get: r => r.metrics?.active_users_per_day, digits: 2, higherIsBetter: true },
  { label: 'Restarts per day', get: r => r.metrics?.restarts_per_day, digits: 2, higherIsBetter: false },
  { label: 'Error rate', get: r => r.metrics?.error_rate, higherIsBetter: false },
  { label: 'p95 response time', get: r => r.metrics?.p95_ms, higherIsBetter: false },
  { label: 'Requests (total)', get: r => r.metrics?.requests },
  { label: 'Active users (total)', get: r => r.metrics?.active_users },
  { label: 'Restarts (total)', get: r => r.metrics?.restarts },
  { label: 'Time live', get: r => r.live_ms, fmt: n => fmtDuration(n) },
]

const name = (r: Release) => `${r.env === 'production' ? 'Prod' : 'Sandbox'} ${r.version ? (r.version.startsWith('v') ? r.version : `v${r.version}`) : `#${r.id}`}${r.label ? ` · ${r.label}` : ''}`

/** Two releases side by side, normalised per day where it matters, with B's change against A. */
export function ReleaseCompare({ a, b, onClose }: { a: Release; b: Release; onClose: () => void }) {
  const [older, newer] = a.id < b.id ? [a, b] : [b, a]
  return (
    <Modal title="Compare releases" onClose={onClose} width={760}>
      <div className="am2-table-wrap" style={{ marginBottom: 0 }}>
        <table className="am2-table" style={{ minWidth: 520 }} aria-label="Release comparison">
          <thead>
            <tr>
              <th className="am2-field" scope="col">Metric</th>
              <th scope="col">{name(older)}</th>
              <th scope="col">{name(newer)}</th>
              <th scope="col">Change</th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map(row => {
              const x = row.get(older)
              const y = row.get(newer)
              const f = row.fmt || ((n: number | null | undefined) => fmtNum(n, row.digits))
              let change = '—'
              let cls = ''
              if (x != null && y != null) {
                if (x === 0) change = y === 0 ? '0%' : 'new'
                else {
                  const pct = ((y - x) / x) * 100
                  change = `${pct > 0 ? '+' : ''}${pct.toFixed(1)}%`
                  if (row.higherIsBetter !== undefined && pct !== 0) cls = (pct > 0) === row.higherIsBetter ? 'am2-up' : 'am2-down'
                }
              }
              return (
                <tr key={row.label}>
                  <td className="am2-field">{row.label}</td>
                  <td>{f(x)}</td>
                  <td>{f(y)}</td>
                  <td className={cls}>{change}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <p className="am2-small am2-dim">Per-day figures divide each release's totals by the days it was live. Error rate and p95 response time are not recorded.</p>
    </Modal>
  )
}
