import { EXTERNAL_REF_LABELS, type ExternalRefSource } from './externalSecretRef'

interface Props {
  source: ExternalRefSource
  reference: string
}

// Shown in place of a masked value: the env var holds only this reference, and
// AppCrane reads the value from the store at each deploy and restart.
export function ExternalSecretRefBadge({ source, reference }: Props) {
  const label = EXTERNAL_REF_LABELS[source]
  return (
    <>
      <span
        className="badge badge-pending"
        data-external-ref={source}
        title={`AppCrane reads this value from ${label} at each deploy and restart, and stores only this reference.`}
        style={{ marginRight: 8, whiteSpace: 'nowrap' }}
      >linked to {label}</span>
      <span data-secret-ref>{reference}</span>
    </>
  )
}
