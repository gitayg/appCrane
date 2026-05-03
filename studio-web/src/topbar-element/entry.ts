// Entry point for the standalone IIFE bundle (docs/shared/crane-topbar.js).
// Loading the script auto-registers the <crane-app-topbar> element.
//
// React side imports defineCraneAppTopbar() from this module directly so
// the element is registered when the admin SPA boots. Vanilla side
// (login.html) gets the same registration via a top-level <script> tag.
import { defineCraneAppTopbar, CraneAppTopbar } from './CraneAppTopbar'

defineCraneAppTopbar()

export { defineCraneAppTopbar, CraneAppTopbar }
