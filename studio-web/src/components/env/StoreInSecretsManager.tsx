interface Props {
  name: string
  checked: boolean
  onChange: (checked: boolean) => void
}

export function StoreInSecretsManager({ name, checked, onChange }: Props) {
  return (
    <label
      title="AppCrane writes the value to AWS Secrets Manager and keeps only a reference to it."
      style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 6, fontSize: '.78rem', color: 'var(--dim)', fontFamily: 'inherit', cursor: 'pointer' }}
    >
      <input
        type="checkbox"
        aria-label={`Store ${name} in Secrets Manager`}
        checked={checked}
        onChange={e => onChange(e.target.checked)}
      />
      Store in Secrets Manager
    </label>
  )
}
