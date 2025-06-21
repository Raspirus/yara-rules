#!/usr/bin/env bash

set -e

FILES="$@"
RESULTS=""
ERRORS=0

if [ -z "$FILES" ]; then
  echo "No YARA files to check ✅"
  echo "message=No YARA files to check ✅" >> $GITHUB_OUTPUT
  exit 0
fi

echo "Checking YARA files:"
for file in $FILES; do
  echo "🔍 Linting $file"
  LINT_OUTPUT=$(yls lint "$file" 2>&1) || true

  if [ -n "$LINT_OUTPUT" ]; then
    RESULTS+="❌ **$file** failed linting\n\`\`\`\n$LINT_OUTPUT\n\`\`\`\n\n"
    ((ERRORS++))
  else
    RESULTS+="✅ **$file** passed linting and validation\n\n"
  fi
done

if [ "$ERRORS" -gt 0 ]; then
  echo -e "$RESULTS"
  echo "message=$RESULTS" >> $GITHUB_OUTPUT
  exit 1
else
  echo -e "$RESULTS"
  echo "message=$RESULTS" >> $GITHUB_OUTPUT
fi
