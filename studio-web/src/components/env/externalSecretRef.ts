// The `source` the env var API reports on a ref+ value, and the store it names.
export type ExternalRefSource = 'vault' | 'infisical' | 'onepassword' | 'aws_ssm'

export const EXTERNAL_REF_LABELS: Record<ExternalRefSource, string> = {
  vault: 'HashiCorp Vault',
  infisical: 'Infisical',
  onepassword: '1Password',
  aws_ssm: 'AWS SSM Parameter Store',
}

export function isExternalRefSource(source: string | undefined | null): source is ExternalRefSource {
  return typeof source === 'string' && Object.prototype.hasOwnProperty.call(EXTERNAL_REF_LABELS, source)
}
