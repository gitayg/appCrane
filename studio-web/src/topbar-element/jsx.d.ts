// JSX intrinsic typing for the <crane-app-topbar> Custom Element so the
// React admin can render it without `any`. Attribute names use kebab-case
// to match the element's observedAttributes contract; React 18+ passes
// these straight through as HTML attributes.
import type { DetailedHTMLProps, HTMLAttributes, ReactNode } from 'react'

interface CraneAppTopbarAttrs extends HTMLAttributes<HTMLElement> {
  'app-name'?:     string
  'app-icon-url'?: string
  'app-slug'?:     string
  'prod-version'?: string
  'sand-version'?: string
  'prod-url'?:     string
  'sand-url'?:     string
  'env'?:          'production' | 'sandbox'
  'current-url'?:  string
  'show-evict'?:   string | boolean
  'folded'?:       string | boolean
  children?:       ReactNode
}

declare module 'react' {
  namespace JSX {
    interface IntrinsicElements {
      'crane-app-topbar': DetailedHTMLProps<CraneAppTopbarAttrs, HTMLElement>
    }
  }
}

export {}
