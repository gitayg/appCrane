export type SinkType = 'syslog' | 'https' | 's3'
export type Severity = 'info' | 'warning' | 'critical'

export interface SecretState { set: boolean; preview?: string }

export interface SinkHealth {
  lag_events: number | string
  lag_seconds: number
  last_success_at: string | null
  last_error: string | null
  failing_since: string | null
  consecutive_failures: number
  cursor_event_id: number
  problem: string | null
}

export interface Sink {
  id: number
  name: string
  type: SinkType
  preset: string
  format: 'json' | 'cef'
  enabled: boolean
  config: Record<string, string | number | boolean>
  has_ca: boolean
  ca_pem: string | null
  tls_skip_verify: boolean
  filters: { kinds: string[]; apps: string[]; min_severity: Severity }
  secrets: Record<string, SecretState>
  delivered_count: number
  last_success_at: string | null
  last_error: string | null
  health: SinkHealth
}

export interface SiemOptions {
  presets: Record<string, { label: string; secrets: string[] }>
  s3_secrets: string[]
}

export interface SiemList {
  sinks: Sink[]
  private_allowlist: string[]
  options: SiemOptions
}

export interface FieldDef { key: string; label: string; placeholder?: string; kind?: 'text' | 'number' | 'bool' }

export const SECRET_LABELS: Record<string, string> = {
  token: 'HEC token', api_key: 'API key', password: 'Password', url: 'Collector URL (contains its token)',
  client_secret: 'Client secret', auth_value: 'Auth header value', secret_access_key: 'Secret access key',
}

const COMMON: FieldDef[] = [
  { key: 'batch_size', label: 'Batch size', kind: 'number', placeholder: '500' },
  { key: 'max_lag_sec', label: 'Max lag before alert (s)', kind: 'number', placeholder: '900' },
  { key: 'alert_after_sec', label: 'Alert after failing for (s)', kind: 'number', placeholder: '300' },
]

export function configFields(type: SinkType, preset: string): FieldDef[] {
  if (type === 'syslog') {
    return [
      { key: 'host', label: 'Host', placeholder: 'siem.internal' },
      { key: 'port', label: 'Port', kind: 'number', placeholder: '6514' },
      { key: 'facility', label: 'Facility', kind: 'number', placeholder: '13' },
      ...COMMON,
    ]
  }
  if (type === 's3') {
    return [
      { key: 'bucket', label: 'Bucket' }, { key: 'region', label: 'Region', placeholder: 'us-east-1' },
      { key: 'endpoint', label: 'Endpoint (R2 / MinIO, optional)', placeholder: 'https://...' },
      { key: 'access_key_id', label: 'Access key ID' }, { key: 'prefix', label: 'Key prefix', placeholder: 'appcrane/' },
      { key: 'flush_sec', label: 'Flush every (s)', kind: 'number', placeholder: '300' },
      { key: 'gzip', label: 'Gzip objects', kind: 'bool' },
      ...COMMON,
    ]
  }
  const gz: FieldDef = { key: 'gzip', label: 'Gzip request bodies', kind: 'bool' }
  switch (preset) {
    case 'splunk': return [{ key: 'url', label: 'HEC base URL', placeholder: 'https://splunk.internal:8088' }, { key: 'index', label: 'Index' }, { key: 'sourcetype', label: 'Sourcetype' }, gz, ...COMMON]
    case 'datadog': return [{ key: 'site', label: 'Site', placeholder: 'datadoghq.com' }, { key: 'url', label: 'Intake URL (overrides site)' }, { key: 'service', label: 'Service' }, { key: 'tags', label: 'Tags' }, gz, ...COMMON]
    case 'elastic': return [{ key: 'url', label: 'Cluster URL', placeholder: 'https://es.internal:9200' }, { key: 'index', label: 'Index / data stream', placeholder: 'appcrane-events' }, { key: 'username', label: 'Username (if not using an API key)' }, gz, ...COMMON]
    case 'sumo': return [{ key: 'category', label: 'Source category' }, gz, ...COMMON]
    case 'sentinel': return [
      { key: 'tenant_id', label: 'Tenant ID' }, { key: 'client_id', label: 'App (client) ID' },
      { key: 'dce_url', label: 'Data collection endpoint', placeholder: 'https://...ingest.monitor.azure.com' },
      { key: 'dcr_id', label: 'DCR immutable ID', placeholder: 'dcr-...' }, { key: 'stream', label: 'Stream', placeholder: 'Custom-AppCrane_CL' },
      gz, ...COMMON]
    default: return [{ key: 'url', label: 'URL', placeholder: 'https://...' }, { key: 'auth_header', label: 'Auth header name', placeholder: 'Authorization' }, gz, ...COMMON]
  }
}
