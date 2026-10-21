'use client'
import { Button } from '@/components/ui/button'
export default function Page() {
  const analytics = process.env.NEXT_PUBLIC_ANALYTICS_ID
  return <main data-analytics={analytics}><Button>Ask</Button></main>
}
