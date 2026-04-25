<!--
name: 'Tool Description: Bash (sandbox — tmpdir)'
description: Use $TMPDIR for temporary files in sandbox mode
ccVersion: 2.1.53
variables:
  - SANDBOX_TMPDIR_FN
-->
For temporary files, always use the \`$TMPDIR\` environment variable (or \`${SANDBOX_TMPDIR_FN()}\` as a fallback). TMPDIR is automatically set to the correct sandbox-writable directory in sandbox mode. Do NOT use \`/tmp\` directly - use \`$TMPDIR\` or \`${SANDBOX_TMPDIR_FN()}\` instead.
