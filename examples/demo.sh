#!/usr/bin/env bash
# Larvanex demo — a short, scripted tour used for the README/social recordings.
# Usage: bash examples/demo.sh   (requires `larvanex` on PATH)

bold=$'\033[1m'; green=$'\033[1;32m'; cyan=$'\033[1;36m'; dim=$'\033[2m'; reset=$'\033[0m'

type_cmd() {
  printf '%s$%s ' "$green" "$reset"
  local cmd="$1"
  for (( i=0; i<${#cmd}; i++ )); do
    printf '%s' "${cmd:$i:1}"
    sleep 0.015
  done
  printf '\n'
  sleep 0.35
}

clear
printf '%s# Larvanex - static malware triage%s\n' "$cyan" "$reset"
printf '%s  it never executes what it scans%s\n\n' "$dim" "$reset"
sleep 1.2

type_cmd "larvanex scan samples/benign/report.pdf"
larvanex scan --no-network samples/benign/report.pdf
sleep 2.2

printf '\n'
type_cmd "larvanex scan --decompose samples/suspicious/hidden_payload.pdf"
larvanex scan --no-network --decompose samples/suspicious/hidden_payload.pdf
sleep 3.0

printf '\n'
type_cmd "larvanex scan -r samples/suspicious --html report.html --attack-layer layer.json"
larvanex scan --no-network -r samples/suspicious --html /tmp/larvanex-report.html --attack-layer /tmp/larvanex-layer.json >/dev/null 2>&1
printf '%s[+]%s wrote report.html + ATT&CK Navigator layer\n' "$green" "$reset"
sleep 2.5

printf '\n%s  22 tests - python 3.9-3.13 - github.com/autod3structeur/Larvanex%s\n' "$cyan" "$reset"
sleep 2.5
