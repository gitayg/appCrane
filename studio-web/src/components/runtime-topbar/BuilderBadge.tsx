import { useBuilderActive } from '../../hooks/useBuilderActive'

interface Props {
  slug: string | null | undefined
}

/**
 * Pill that shows "Builder Working" while a container (Ask or AppStudio
 * code job) is live for the app. Hidden otherwise. Same trigger as the
 * portal iframe topbar.
 */
export function BuilderBadge({ slug }: Props) {
  const active = useBuilderActive(slug)
  if (!active) return null
  return (
    <div className="builder-badge">
      <span className="builder-badge-dot" />
      Builder Working
    </div>
  )
}
