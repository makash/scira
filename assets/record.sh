#!/usr/bin/env bash

simulate_typing() {
    local text="$1"
    for (( i=0; i<${#text}; i++ )); do
        printf '%s' "${text:$i:1}"
        sleep 0.03
    done
}

prompt() {
    printf '\033[1;34m❯\033[0m '
}

ok() {
    printf '  \033[1;32m✓\033[0m %s\n' "$1"
}

warn() {
    printf '  \033[1;33m!\033[0m %s\n' "$1"
}

sleep_brief() {
    sleep 0.35
}

clear
sleep 0.4
printf '\033[1mSCIRA demo\033[0m\n'
printf '  Host-side supply chain incident response agent\n\n'
sleep 1.0

prompt
simulate_typing "scira scan litellm --target /srv/app"
sleep_brief
echo ""
sleep 0.5
printf '\033[1mStatus:\033[0m likely_affected\n\n'
warn "Found compromised version 1.82.8 in /srv/app/requirements.txt"
warn "Found IOC domain models.litellm.cloud in logs/app.log"

printf '\n\033[1mImmediate next steps:\033[0m\n'
printf '1. Isolate the host or runner\n'
printf '2. Preserve evidence before cleanup\n'
printf '3. Rotate credentials in scope\n'
sleep 2.2

echo ""
printf 'Scan complete. Would you like an AI explanation and remediation summary? [Y/n] '
sleep 0.8
printf 'y\n'
sleep 0.7

echo ""
printf '\033[1mAI explanation\033[0m\n'
printf 'Provider: anthropic\n'
printf 'Model: claude-3-5-sonnet-latest\n\n'
sleep 0.8
printf '\033[1mExecutive summary\033[0m\n'
printf 'This environment appears likely affected because a compromised\n'
printf 'LiteLLM version was found alongside IOC evidence.\n\n'
sleep 1.1
printf '\033[1mPriority actions\033[0m\n'
ok "Isolate the affected host or runner"
ok "Rotate cloud, git, and SSH credentials"
ok "Rebuild from a known-good dependency state"

printf '\n\033[1mVerification warning\033[0m\n'
printf 'Recommendations are advisory. Verify before destructive action.\n'
sleep 2.0
