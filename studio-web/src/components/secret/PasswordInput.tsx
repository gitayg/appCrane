import { forwardRef, useState, type InputHTMLAttributes } from 'react'
import { Icon } from '../icons'
import { formInputStyle } from '../formHelpers'

// A field the user types a secret into. The eye only flips the field between
// dots and text on this screen: no server call, no audit, no alert. Callers
// never pre-fill it with a stored secret; "leave blank to keep" goes in the
// placeholder instead.

export interface PasswordInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label: string
  styled?: boolean
}

export const PasswordInput = forwardRef<HTMLInputElement, PasswordInputProps>(function PasswordInput(
  { label, styled, style, disabled, ...rest }, ref,
) {
  const [visible, setVisible] = useState(false)
  const inputStyle = styled ? { ...formInputStyle, ...style } : style
  return (
    <span className="password-input" style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', width: (style?.width ?? (styled ? '100%' : undefined)) as string | number | undefined }}>
      <input
        {...rest}
        ref={ref}
        type={visible ? 'text' : 'password'}
        disabled={disabled}
        aria-label={rest['aria-label'] ?? label}
        style={{ ...inputStyle, width: '100%', paddingRight: 30, boxSizing: 'border-box' }}
        onFocus={e => { if (styled) e.currentTarget.style.borderColor = 'var(--accent)'; rest.onFocus?.(e) }}
        onBlur={e => { if (styled) e.currentTarget.style.borderColor = 'var(--border)'; rest.onBlur?.(e) }}
      />
      <button
        type="button"
        aria-label={visible ? `Hide ${label}` : `Show ${label}`}
        aria-pressed={visible}
        title={visible ? `Hide ${label}` : `Show ${label}`}
        disabled={disabled}
        onClick={() => setVisible(v => !v)}
        style={{
          position: 'absolute', right: 4, top: '50%', transform: 'translateY(-50%)',
          background: 'none', border: 'none', padding: 2, cursor: disabled ? 'default' : 'pointer',
          color: 'var(--dim)', display: 'inline-flex', alignItems: 'center',
        }}
      >
        {visible ? <Icon.EyeOff size={14} /> : <Icon.Eye size={14} />}
      </button>
    </span>
  )
})
