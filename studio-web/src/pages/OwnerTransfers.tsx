import { OwnerTransferInbox } from '../components/ownership/OwnerTransferInbox'

export function OwnerTransfers() {
  return (
    <div className="container">
      <h2 style={{ marginTop: 0 }}>Owner requests</h2>
      <OwnerTransferInbox />
    </div>
  )
}
