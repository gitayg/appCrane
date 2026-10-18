import React from 'react'
import ReactDOM from 'react-dom/client'
import { AdminApp } from './AdminApp'
import './admin.css'
import './styles.css'

// The tab says which AppCrane this is: several instances look identical otherwise.
document.title = `${window.location.hostname} - AppCrane`

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AdminApp />
  </React.StrictMode>,
)
