import type { ReactNode } from 'react'
import { ENV_LABEL, type EnvName } from './types'

export interface EnvRow {
  key: string
  label: ReactNode
  production?: ReactNode
  sandbox?: ReactNode
  /** One value for the whole app, shown across both environment columns. */
  both?: ReactNode
  diff?: boolean
}

export type EnvDot = 'green' | 'red' | 'yellow' | 'gray'

/**
 * Field | Production | Sandbox. The wrapper scrolls sideways on a narrow
 * screen and the field column stays put; the table never turns into cards.
 */
export function EnvTable({ rows, dots, onPromote, promoteTitle, caption }: {
  rows: EnvRow[]
  dots?: Partial<Record<EnvName, EnvDot>>
  onPromote?: () => void
  promoteTitle?: string
  caption?: string
}) {
  const head = (env: EnvName) => (
    <th className="am2-env" scope="col">
      <span className="am2-envhead">
        <span className={`dot dot-${dots?.[env] ?? 'gray'}`} aria-hidden="true" />
        <span className="grow">{ENV_LABEL[env]}</span>
        {env === 'sandbox' && onPromote && (
          <button className="btn btn-xs" onClick={onPromote} title={promoteTitle || 'Promote the live sandbox release to production'}>Promote</button>
        )}
      </span>
    </th>
  )
  return (
    <div className="am2-table-wrap">
      <table className="am2-table" aria-label={caption}>
        <thead>
          <tr>
            <th className="am2-field" scope="col">Field</th>
            {head('production')}
            {head('sandbox')}
          </tr>
        </thead>
        <tbody>
          {rows.map(r => (
            <tr key={r.key} className={r.diff ? 'am2-diff' : undefined}>
              <td className="am2-field">{r.label}</td>
              {r.both !== undefined
                ? <td className="am2-env" colSpan={2}>{r.both}</td>
                : <>
                    <td className="am2-env">{r.production ?? <span className="am2-dim">—</span>}</td>
                    <td className="am2-env">{r.sandbox ?? <span className="am2-dim">—</span>}</td>
                  </>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
