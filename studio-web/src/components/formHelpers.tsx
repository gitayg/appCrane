// Form helpers shared between Settings sub-tabs and the Branding tab
// (now under AppStudio). Extracted from pages/Settings.tsx so both
// surfaces use the same input styling and saved-flash behavior.

import { useState, useRef } from 'react'

export const formInputStyle: React.CSSProperties = {
  background: 'var(--surface2)',
  border: '1px solid var(--border)',
  color: 'var(--text)',
  padding: '8px 12px',
  borderRadius: 6,
  width: '100%',
  fontSize: '.85rem',
  fontFamily: 'inherit',
  outline: 'none',
  boxSizing: 'border-box',
}

/** [shown, flash()] — flips true for ~2.5s when flash() is called. */
export function useFlash(): [boolean, () => void] {
  const [show, setShow] = useState(false)
  const t = useRef<ReturnType<typeof setTimeout> | null>(null)
  const flash = () => {
    setShow(true)
    if (t.current) clearTimeout(t.current)
    t.current = setTimeout(() => setShow(false), 2500)
  }
  return [show, flash]
}

export function FocusInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      style={{ ...formInputStyle, ...props.style }}
      onFocus={e => {
        e.currentTarget.style.borderColor = 'var(--accent)'
        props.onFocus?.(e)
      }}
      onBlur={e => {
        e.currentTarget.style.borderColor = 'var(--border)'
        props.onBlur?.(e)
      }}
    />
  )
}

export function FocusTextarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      style={{ ...formInputStyle, resize: 'vertical', ...props.style }}
      onFocus={e => {
        e.currentTarget.style.borderColor = 'var(--accent)'
        props.onFocus?.(e)
      }}
      onBlur={e => {
        e.currentTarget.style.borderColor = 'var(--border)'
        props.onBlur?.(e)
      }}
    />
  )
}
