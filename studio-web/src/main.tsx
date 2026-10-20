import React from 'react'
import ReactDOM from 'react-dom/client'
import { AdminApp } from './AdminApp'
import { ErrorBoundary } from './components/ErrorBoundary'
import { installClientErrorReporter } from './lib/clientErrors'
import { authHeaders } from './adminApi'
import './admin.css'
import './styles.css'

installClientErrorReporter({ source: 'admin', headers: authHeaders })

// The tab says which AppCrane this is: several instances look identical otherwise.
document.title = `${window.location.hostname} - AppCrane`

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <AdminApp />
    </ErrorBoundary>
  </React.StrictMode>,
)
