interface OffSite { bucket: string; prefix: string; last_run: string | null; holds: string[]; note: string }
interface TrashBackup { id: number; env: string; created_at: string; size_bytes: number; file_path: string }
export interface TrashDetail { backups?: TrashBackup[]; off_site?: OffSite }

// What a trash entry carried with it: the backups rows of a deleted app (their
// files are inside the entry) and the off-site copies AppCrane leaves in place.
export default function TrashEntryDetail({ detail }: { detail: TrashDetail | null }) {
  if (!detail) return null
  const { backups, off_site: offSite } = detail
  return (
    <div style={{ fontSize: '.8rem', color: 'var(--dim)', marginLeft: 12 }}>
      {backups && backups.length > 0 && (
        <div>
          {backups.length} backup(s) inside this entry:{' '}
          {backups.map(b => `#${b.id} ${b.env} ${b.created_at} (${b.size_bytes} bytes)`).join(', ')}
        </div>
      )}
      {offSite && (
        <div>
          Off-site copies not deleted, in bucket <b>{offSite.bucket}</b> under <code>{offSite.prefix || '(no prefix)'}</code>
          {' '}(last upload {offSite.last_run || 'unknown'}): {offSite.holds.join('; ')}. {offSite.note}
        </div>
      )}
    </div>
  )
}
