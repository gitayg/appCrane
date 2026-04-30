import React from 'react'
import ReactDOM from 'react-dom/client'
import { AdminApp } from './AdminApp'
import './admin.css'
import './styles.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AdminApp />
  </React.StrictMode>,
)
