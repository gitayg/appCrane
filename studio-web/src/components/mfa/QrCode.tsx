import { useMemo } from 'react'
import { encodeQr, qrPath } from './qr'

// The otpauth:// URI as a QR code, drawn client-side: the secret never leaves
// the page for an image service.
export function QrCode({ value, px = 200 }: { value: string; px?: number }) {
  const { d, size } = useMemo(() => qrPath(encodeQr(value)), [value])
  return (
    <svg role="img" aria-label="QR code for your authenticator app" width={px} height={px}
      viewBox={`0 0 ${size} ${size}`} shapeRendering="crispEdges" style={{ background: '#fff', borderRadius: 4 }}>
      <path d={d} fill="#000" />
    </svg>
  )
}
