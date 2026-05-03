// Entry point for the standalone IIFE bundle (docs/shared/crane-topbar.js).
// Loading the script auto-registers <crane-app-topbar> AND the panel
// elements (<crane-ask-panel>, <crane-request-panel>, <crane-bug-panel>)
// so portal pages can drop them in without their own React install.
//
// React side imports the same defineXxx() functions directly so the
// elements are registered when the admin SPA boots. Vanilla side
// (login.html) gets the same registration via a top-level <script> tag.
import { defineCraneAppTopbar, CraneAppTopbar } from './CraneAppTopbar'
import { defineCranePanels, CraneAskPanel, CraneRequestPanel, CraneBugPanel } from './CranePanels'

defineCraneAppTopbar()
defineCranePanels()

export { defineCraneAppTopbar, CraneAppTopbar }
export { defineCranePanels, CraneAskPanel, CraneRequestPanel, CraneBugPanel }
