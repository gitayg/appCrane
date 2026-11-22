---
name: help
description: List the work-review plugin's commands with what each does, read from the installed plugin rather than from memory.
disable-model-invocation: true
---

# work-review commands

Read from the installed plugin:

!`for f in "${CLAUDE_PLUGIN_ROOT}"/skills/*/SKILL.md; do n=$(sed -n 's/^name: *//p' "$f" | head -1); h=$(sed -n 's/^argument-hint: *//p' "$f" | head -1 | tr -d '"'); d=$(sed -n 's/^description: *//p' "$f" | head -1 | cut -c1-200); echo "- /work-review:$n $h — $d"; done; v=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json"); echo; echo "Plugin version: $v"`

Show that list to the user as it is, then say in one line: run `/work-review` for a review, then `/work-review:apply` with the fix numbers to apply them. If the list above is empty or shows an error, say the plugin's files could not be read rather than listing commands from memory.
