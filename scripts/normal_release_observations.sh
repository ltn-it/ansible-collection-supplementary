#!/usr/bin/env bash
set -euo pipefail

# Raw, bounded transport only. Protected Main proof code inside Devtools owns
# every identity, policy, artifact, approval, signature and publication decision.
mode="$1"; destination="$2"; repository="$3"; revision="$4"
test "$repository" = lightning-it/ansible-collection-supplementary
[[ "$revision" =~ ^[0-9a-f]{40}$ ]]
prefix="repos/$repository"
test ! -e "$destination"
mkdir -m 0755 "$destination"
printf '{"version":1,"repository":"%s","calls":{},"logs":{},"artifacts":{},"assets":{}}\n' \
  "$repository" >"$destination/index.json"
transport_bound() {
  test "$(find "$destination" -type f | wc -l)" -le 4097
  test "$(find "$destination" -type f ! -name 'asset-*.bin' -exec wc -c {} + \
    | awk '$NF != "total" {sum+=$1} END {print sum+0}')" -le 134217728
  test "$(find "$destination" -type f -name 'asset-*.bin' -exec wc -c {} + \
    | awk '$NF != "total" {sum+=$1} END {print sum+0}')" -le 16000000000
}
index_read() {
  jq --arg kind "$1" --arg key "$2" --arg file "$3" '.[$kind][$key]=$file' \
    "$destination/index.json" >"$destination/index.next"
  mv "$destination/index.next" "$destination/index.json"
  transport_bound
}
observe() {
  local path="$1" name
  [[ "$path" == "$prefix" || "$path" == "$prefix/"* ]]
  name="$(jq -r --arg path "$path" '.calls[$path] // empty' "$destination/index.json")"
  if [ -z "$name" ]; then
    name="read-$(jq '.calls | length' "$destination/index.json").json"
    gh api --method GET "$path" >"$destination/$name"
    test "$(wc -c <"$destination/$name")" -le 52428800
    index_read calls "$path" "$name"
  fi
  observed_file="$destination/$name"
}
list_number=0
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
observe_pages() {
  local path="$1" key="$2" separator='?' count page list
  [[ "$path" != *'?'* ]] || separator='&'
  list_number=$((list_number+1)); list="$scratch/list-$list_number.jsonl"; : >"$list"
  for page in $(seq 1 100); do
    observe "$path${separator}per_page=100&page=$page"
    jq -c --arg key "$key" 'if $key == "" then . else .[$key] end | .[]' "$observed_file" >>"$list"
    count="$(jq --arg key "$key" 'if $key == "" then . else .[$key] end | length' "$observed_file")"
    if [ "$count" -lt 100 ]; then observed_list="$list"; return; fi
  done
  echo '::error::Native observation pagination incomplete.' >&2; exit 1
}
if [ "$mode" = fresh ]; then
  initial="$5"
  while read -r path; do observe "$path"; done < <(jq -r '.calls | keys[]' "$initial/index.json")
  chmod -R a+rX "$destination"
  exit 0
fi
case "$mode" in publication|baseline|completion) ;; *) exit 1;; esac
observe "$prefix"
for ref in main develop; do
  observe "$prefix/branches/$ref"; observe "$prefix/git/ref/heads/$ref"
done
# The receipt is a locator, not accepted evidence. The EE re-reads its actual Git
# object and authenticates its complete preparation and native relationships.
git show "$revision:changelogs/release-preparation.json" >"$scratch/receipt.json"
version="$(jq -er .next_version "$scratch/receipt.json")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
tag="v$version"
observe_pages "$prefix/releases" ''
matched="$scratch/published.json"
jq -sc --arg tag "$tag" '[.[] | select(.tag_name == $tag)]' "$observed_list" >"$matched"
if [ "$(jq length "$matched")" -gt 0 ]; then
  observe "$prefix/releases/tags/$tag"; published="$observed_file"
  observe "$prefix/git/ref/tags/$tag"
  if [ "$(jq -r .object.type "$observed_file")" = tag ]; then
    observe "$prefix/git/tags/$(jq -er .object.sha "$observed_file")"
  fi
  test "$(jq '.assets | length' "$published")" -le 128
  while read -r asset; do
    [[ "$asset" =~ ^[1-9][0-9]*$ ]]
    gh api --method GET --header 'Accept: application/octet-stream' \
      "$prefix/releases/assets/$asset" >"$destination/asset-$asset.bin"
    test "$(wc -c <"$destination/asset-$asset.bin")" -le 2000000000
    index_read assets "$asset" "asset-$asset.bin"
  done < <(jq -r '.assets[] | select(.digest == null or (.name | test(
    "^(normal-release-native-evidence\\.(json|sigstore\\.json)|post-release-verification\\.json(\\.sigstore\\.json)?)$"))) | .id' "$published")
  # Existing signed archives retain the original native observations. Current
  # publication candidate quality remains independently live in its own job.
  chmod -R a+rX "$destination"
  exit 0
fi
# Missing publication is data; baseline/completion validation must reject it in
# EE. Only an unpublished publication captures live original ingress proof.
if [ "$mode" != publication ]; then chmod -R a+rX "$destination"; exit 0; fi
: >"$scratch/heads"; : >"$scratch/runs"
for merge in "$revision" "$(git show -s --format=%P "$revision" | awk '{print $2}')"; do
  [[ "$merge" =~ ^[0-9a-f]{40}$ ]]
  observe_pages "$prefix/commits/$merge/pulls" ''
  test "$(wc -l <"$observed_list")" -le 32
  cp "$observed_list" "$scratch/pulls"
  while read -r number; do
    [[ "$number" =~ ^[1-9][0-9]*$ ]]
    observe "$prefix/pulls/$number"
    jq -er '.head.sha' "$observed_file" >>"$scratch/heads"
    base="$(jq -er .base.sha "$observed_file")"
    [[ "$base" =~ ^[0-9a-f]{40}$ ]]
    observe "$prefix/contents/.lit/workflow-control.json?ref=$base"
    observe_pages "$prefix/issues/$number/events" ''
  done < <(jq -r .number "$scratch/pulls")
done
sort -u "$scratch/heads" >"$scratch/unique-heads"
test "$(wc -l <"$scratch/unique-heads")" -le 32
while read -r head; do
  [[ "$head" =~ ^[0-9a-f]{40}$ ]]
  observe_pages "$prefix/actions/runs?head_sha=$head" workflow_runs
  jq -r 'select(.workflow_url | contains("/actions/required_workflows/")) | .id' \
    "$observed_list" >>"$scratch/runs"
done <"$scratch/unique-heads"
prepare_run="$(jq -er .workflow.run_id "$scratch/receipt.json")"
printf '%s\n' "$prepare_run" >>"$scratch/runs"
sort -u "$scratch/runs" >"$scratch/unique-runs"
test "$(wc -l <"$scratch/unique-runs")" -le 33
while read -r run; do
  [[ "$run" =~ ^[1-9][0-9]*$ ]]
  observe "$prefix/actions/runs/$run"; run_file="$observed_file"
  if [ "$run" != "$prepare_run" ]; then
    attempts="$(jq -er .run_attempt "$run_file")"
    [[ "$attempts" =~ ^[1-9][0-9]*$ ]] && test "$attempts" -le 100
    observe "$prefix/actions/runs/$run/approvals"
    for attempt in $(seq 1 "$attempts"); do
      observe "$prefix/actions/runs/$run/attempts/$attempt"
      observe_pages "$prefix/actions/runs/$run/attempts/$attempt/jobs" jobs
      while read -r job; do
        [[ "$job" =~ ^[1-9][0-9]*$ ]]
        gh api --method GET "$prefix/actions/jobs/$job/logs" >"$destination/log-$job.txt"
        test "$(wc -c <"$destination/log-$job.txt")" -le 262144
        index_read logs "$job" "log-$job.txt"
      done < <(jq -r 'select(.name == "Current revision review" and .conclusion == "failure") | .id' "$observed_list")
    done
  fi
  observe_pages "$prefix/actions/runs/$run/artifacts" artifacts
  while read -r artifact; do
    [[ "$artifact" =~ ^[1-9][0-9]*$ ]]
    gh api --method GET "$prefix/actions/artifacts/$artifact/zip" >"$destination/artifact-$artifact.zip"
    test "$(wc -c <"$destination/artifact-$artifact.zip")" -le 52432896
    index_read artifacts "$artifact" "artifact-$artifact.zip"
  done < <(jq -r 'select(.expired == false and (.name | test(
    "^(control-(proof|operation)|normal-release-preparation)-[1-9][0-9]*$"))) | .id' "$observed_list")
done <"$scratch/unique-runs"
observe "$prefix/environments/normal-release-promotion-approval"
chmod -R a+rX "$destination"
