import type { CoderGap } from './api'

/**
 * What the Coder panel shows when the coder cannot run for this user on this
 * app — instead of hiding the button, which is what it used to do.
 *
 * A hidden button teaches nothing: the user never learns the feature exists,
 * let alone what it would take. So every gap the server reports is shown at
 * once, with its fix, in order. Fixing one and meeting the next is exactly the
 * experience this replaces.
 */
export function CoderUnavailable({ gaps, appName }: { gaps: CoderGap[]; appName: string }) {
  return (
    <div className="coder-unavailable">
      <p className="coder-unavailable-lead">
        The coder can change {appName} by talking to you about it, and release what it changes to sandbox.
        {gaps.length === 1 ? ' One thing stands in the way:' : ` ${gaps.length} things stand in the way:`}
      </p>
      <ol className="coder-gaps">
        {gaps.map((g) => (
          <li key={g.code} className="coder-gap">
            <div className="coder-gap-title">{g.title}</div>
            <p className="coder-gap-detail">{g.detail}</p>
            <p className="coder-gap-fix">
              {g.href
                ? <a href={g.href}>{g.fix}</a>
                : g.fix}
            </p>
          </li>
        ))}
      </ol>
    </div>
  )
}
