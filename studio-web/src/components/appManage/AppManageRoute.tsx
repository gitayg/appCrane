import { useSearchParams } from 'react-router-dom'
import { AppManager } from '../../pages/AppManager'
import { AppManagePage } from './AppManagePage'

/** /app: the manage page for ?slug=, or the old app picker when no slug is given. */
export function AppManageRoute() {
  const [params] = useSearchParams()
  const slug = params.get('slug')
  return slug ? <AppManagePage key={slug} slug={slug} /> : <AppManager />
}
