import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'
import { reportClientError } from '../lib/clientErrors'

interface State { failed: boolean }

export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { failed: false }

  static getDerivedStateFromError(): State {
    return { failed: true }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    if (info.componentStack && error instanceof Error && !error.stack) error.stack = info.componentStack
    reportClientError(error)
  }

  render() {
    if (!this.state.failed) return this.props.children
    return (
      <div role="alert" style={{ padding: 32, maxWidth: 520, margin: '10vh auto', color: 'var(--text)' }}>
        <h2 style={{ marginTop: 0 }}>Something went wrong</h2>
        <p style={{ color: 'var(--dim)' }}>This page hit an unexpected error. It has been reported to the platform admins.</p>
        <button className="btn btn-accent" onClick={() => window.location.reload()}>Reload</button>
      </div>
    )
  }
}
