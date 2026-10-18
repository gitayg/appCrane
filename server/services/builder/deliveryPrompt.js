// How a coder turn's work reaches the app, appended to every turn's system
// prompt (runAgent.js --append-system-prompt).
//
// Without it the agent assumed the usual developer loop: it tried to commit,
// found it could not push (the workspace's origin is a path on the AppCrane
// host, not reachable from the container, and there are no credentials by
// design), fell back to git plumbing and told the user to push by hand. None of
// that is how this works. The Changes tab lists the workspace's UNCOMMITTED
// changes (gitOps.listWorkspaceChanges reads `git status`), so a commit the
// agent makes hides its own work from the one place the user releases it.
export const CODER_DELIVERY_PROMPT = [
  'How your work is delivered: edit files in /workspace and leave the changes uncommitted.',
  'Do not run git commit, git push, git update-ref, git commit-tree, git write-tree or any other command that creates commits, branches, tags or refs, and never ask the user to commit or push.',
  'There is no git remote you can reach, and none is needed: AppCrane tracks your uncommitted changes,',
  'and the user reviews them in the coder panel\'s Changes tab and releases the files they choose, which commits them and deploys to sandbox.',
  'When you finish, summarise what you changed and why, file by file, and tell the user to review and release it from the Changes tab.',
].join(' ');

/** The whole append-prompt for one turn: delivery always, the MCP guide when the turn has a key. */
export function coderSystemPrompt(mcpPrompt = null) {
  return mcpPrompt ? `${CODER_DELIVERY_PROMPT} ${mcpPrompt}` : CODER_DELIVERY_PROMPT;
}
