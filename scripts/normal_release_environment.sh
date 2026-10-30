#!/usr/bin/env bash
# Sourced only from the exact protected Main Git blob; caller owns credentials.
: "${workflow_source:?protected Main tooling required}"

# LI-360 normal EE transport:start
# Independent ordinary clones keep executable Main tooling separate from
# Develop data. Only this disposable parent is writable in the EE.
normal_ee_space=""
if [ "$SECURITY_RELEASE" = false ]; then
  normal_ee_space="$RUNNER_TEMP/normal-release-ee"
  test ! -e "$normal_ee_space"
  mkdir -m 0700 "$normal_ee_space"
  git clone --quiet --no-hardlinks --no-checkout "$GITHUB_WORKSPACE" "$normal_ee_space/main"
  git -C "$normal_ee_space/main" checkout --quiet --detach "$WORKFLOW_SOURCE_SHA"
  git clone --quiet --no-hardlinks --no-checkout "$GITHUB_WORKSPACE" "$normal_ee_space/data"
  git -C "$normal_ee_space/data" checkout --quiet --detach "$BASE_SHA"
  mkdir "$normal_ee_space/output"
fi
# Workflow version-resolution calls pass optional arguments across this sourced
# file boundary; the initial input-only call deliberately passes none.
# shellcheck disable=SC2120
release_data() {
  local operation="$RUNNER_TEMP/release-data-operation.sh" name fragment
  cat >"$operation"
  if [ "$SECURITY_RELEASE" = true ]; then
    # Preserve the independently owned Security route.
    # Literal operation written immediately above.
    # shellcheck disable=SC1090
    source "$operation"
    return
  fi
  cp "$operation" "$normal_ee_space/operation.sh"
  : >"$normal_ee_space/context.sh"
  # Fixed nonsecret context only; App/GitHub credentials never enter EE.
  for name in VERSION VERSION_INPUT BASE_SHA WORKFLOW_SOURCE_SHA CREATE_GITHUB_RELEASE \
      PUBLISH_GALAXY GITHUB_REPOSITORY REPOSITORY_ID GITHUB_RUN_ID GITHUB_RUN_ATTEMPT \
      WORKFLOW_REF WORKFLOW_EVENT WORKFLOW_ACTOR SECURITY_RELEASE PREPARATION_MODE pushed_sha; do
    printf 'export %s=%q\n' "$name" "${!name-}" >>"$normal_ee_space/context.sh"
  done
  if ! (
    cd "$normal_ee_space"
    WUNDER_DEVTOOLS_WORKSPACE_MODE=rw WUNDER_DEVTOOLS_RUN_AS_HOST_UID=1 \
      bash "$workflow_source/scripts/wunder-devtools-ee.sh" bash -c '
        set -euo pipefail
        source /workspace/context.sh
        export workflow_source=/workspace/main GITHUB_WORKSPACE=/workspace/data
        export RUNNER_TEMP=/workspace/output PYTHONDONTWRITEBYTECODE=1
        unset PYTHONPATH PYTHONHOME ANSIBLE_CONFIG
        cd /workspace/data
        source /workspace/operation.sh
      ' normal-release-data "$@"
  ); then
    return 1
  fi
  # Return only the fixed generated outputs and consumed fragments.
  for name in galaxy.yml CHANGELOG.rst changelogs/changelog.yaml \
      changelogs/.plugin-cache.yaml changelogs/release-preparation.json; do
    if [ -f "$normal_ee_space/data/$name" ]; then
      cp "$normal_ee_space/data/$name" "$GITHUB_WORKSPACE/$name"
    fi
  done
  while IFS= read -r -d '' fragment; do
    if [ ! -e "$normal_ee_space/data/changelogs/fragments/${fragment##*/}" ]; then
      rm -- "$fragment"
    fi
  done < <(find "$GITHUB_WORKSPACE/changelogs/fragments" -maxdepth 1 -type f \
    \( -name '*.yml' -o -name '*.yaml' \) -print0)
  for name in "$normal_ee_space/output"/*.tar.gz; do
    [ ! -f "$name" ] || cp "$name" "$GITHUB_WORKSPACE/"
  done
}
# LI-360 normal EE transport:end

# LI-344 regular generation inputs:start
# shellcheck disable=SC2119
release_data <<'RELEASE_INPUTS'
python -I - <<'PYINPUT'
from pathlib import Path

for name in ("galaxy.yml", "CHANGELOG.rst", "changelogs/changelog.yaml",
             "changelogs/.plugin-cache.yaml", "changelogs/release-preparation.json"):
    path = Path(name)
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise SystemExit("release input/write target must not be a symlink")
    if path.exists() and (not path.is_file() or path.stat().st_size > 16 * 1024 * 1024):
        raise SystemExit("bounded regular release input required")
fragments = Path("changelogs/fragments")
if fragments.is_symlink() or not fragments.is_dir() or fragments.parent.is_symlink():
    raise SystemExit("regular fragment directory required")
for path in fragments.iterdir():
    if path.suffix in {".yml", ".yaml"} and (path.is_symlink() or not path.is_file()):
        raise SystemExit("regular fragment input required")
PYINPUT
RELEASE_INPUTS
# LI-344 regular generation inputs:end
