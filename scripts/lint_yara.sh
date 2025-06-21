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

for file in $FILES; do
  echo "▶ Linting and validating $file"
  FILE_RESULT=""

  # Validate syntax
  SYNTAX_OUTPUT=$(yr compile "$file" 2>&1) || true
  if [ -n "$SYNTAX_OUTPUT" ]; then
    FILE_RESULT+="❌ **$file** failed validation\n\`\`\`\n$SYNTAX_OUTPUT\n\`\`\`\n"
    ((ERRORS++))
  else
    FILE_RESULT+="✅ **$file** passed syntax check\n"
  fi

  # Check formatting
  FMT_OUTPUT=$(yr fmt -c "$file" 2>&1) || true
  if [ $? -ne 0 ]; then
    FILE_RESULT+="⚠️ **$file** has formatting issues\n\`\`\`\n$FMT_OUTPUT\n\`\`\`\n"
    ((ERRORS++))
  else
    FILE_RESULT+="✅ **$file** is properly formatted\n"
  fi

  RESULTS+="$FILE_RESULT\n"
done

# Output result
echo -e "$RESULTS"
echo "message<<EOF" >> $GITHUB_OUTPUT
echo -e "$RESULTS" >> $GITHUB_OUTPUT
echo "EOF" >> $GITHUB_OUTPUT

if [ "$ERRORS" -gt 0 ]; then
  exit 1
fi

