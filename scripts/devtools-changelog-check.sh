#!/usr/bin/env bash
set -euo pipefail

# Run the same changelog policy used by GitHub PR checks inside the devtools
# container. In GitHub, BASE_SHA/HEAD_SHA come from the PR event. Locally, the
# script compares the current branch with origin/develop when possible and adds
# staged changes so pre-commit can catch missing fragments before commit.

# GitHub push events expose the protected target through GITHUB_REF_NAME while
# the container contract already forwards GITHUB_BASE_REF. Bind the former to
# the latter before entering the pinned container instead of widening the
# centrally governed container environment surface.
if [ "${GITHUB_EVENT_NAME:-}" = push ] && [ -z "${GITHUB_BASE_REF:-}" ]; then
  export GITHUB_BASE_REF="${GITHUB_REF_NAME:-}"
fi

# Keep the actual native repository ID at this existing caller boundary. The
# container receives no additional environment or self-asserted admission flag.
if [[ "${GITHUB_HEAD_REF:-}" == release/v* ]] && [ "${GITHUB_BASE_REF:-}" = develop ] && \
    [ -n "${GITHUB_EVENT_NAME:-}" ]; then
  test "${GITHUB_REPOSITORY:-}" = lightning-it/ansible-collection-supplementary
  test "${GITHUB_REPOSITORY_ID:-}" = 1103407173
fi

bash scripts/wunder-devtools-ee.sh bash -lc '
  set -euo pipefail

  cd /workspace
  git config --global --add safe.directory /workspace >/dev/null

  antsibull-changelog lint

  diff_names() {
    git diff --name-only "$@"
  }

  changed=""
  if [ -n "${BASE_SHA:-}" ] && [ -n "${HEAD_SHA:-}" ]; then
    changed="$(diff_names "$BASE_SHA" "$HEAD_SHA")"
  elif [ -n "${PRE_COMMIT_FROM_REF:-}" ] && [ -n "${PRE_COMMIT_TO_REF:-}" ]; then
    changed="$(diff_names "$PRE_COMMIT_FROM_REF" "$PRE_COMMIT_TO_REF")"
  else
    base_ref="${CHANGELOG_BASE_REF:-origin/develop}"
    if git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
      merge_base="$(git merge-base "$base_ref" HEAD)"
      if [ -n "${merge_base:-}" ]; then
        changed="$(diff_names "$merge_base" HEAD)"
      fi
    fi

    staged="$(diff_names --cached)"
    unstaged="$(diff_names)"
    changed="$(printf "%s\n%s\n%s\n" "$changed" "$staged" "$unstaged" | sed "/^$/d" | sort -u)"
  fi

  changed="$(printf "%s\n" "$changed" | sed "/^$/d" | sort -u)"
  if [ -z "$changed" ]; then
    echo "No changed files detected for changelog policy."
    exit 0
  fi

  echo "$changed"

  labels="$(jq -r ".[]" <<<"${LABELS_JSON:-[]}")"
  has_label() {
    grep -Fxq "$1" <<<"$labels"
  }

  generated_re="^(CHANGELOG\\.(md|rst)|changelogs/(changelog|\\.plugin-cache)\\.yaml)$"
  is_release_branch=false
  is_trusted_release_branch=false
  is_release_promotion=false
  is_published_baseline_import=false
  head_ref="${GITHUB_HEAD_REF:-$(git rev-parse --abbrev-ref HEAD)}"
  base_ref="${GITHUB_BASE_REF:-${GITHUB_REF_NAME:-}}"
  release_pr_author="${GITHUB_PR_AUTHOR:-${PR_AUTHOR:-}}"
  head_ref="$(bash scripts/resolve-changelog-head-ref.sh "$head_ref")"

  # Recover only the exact local candidate of a deterministic integration test.
  # This grants no identity: the independent published-byte proof still runs.
  import_pattern="^reconcile/release-v((0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*))-to-develop$"
  if [ -z "${GITHUB_EVENT_NAME:-}" ] && [ "$head_ref" = HEAD ] && \
      [ "$(git log -1 --format=%s HEAD)" = "Synthetic pull-request integration" ]; then
    read -r -a import_parents <<<"$(git rev-list --parents -n 1 HEAD)"
    if [ "${#import_parents[@]}" -eq 3 ] && \
        [ "$(git rev-parse HEAD^{tree})" = "$(git rev-parse "${import_parents[2]}^{tree}")" ]; then
      import_refs=()
      while IFS= read -r import_ref; do
        if [[ "$import_ref" =~ $import_pattern ]]; then import_refs+=("$import_ref"); fi
      done < <(git for-each-ref --format="%(refname:short)" --points-at "${import_parents[2]}" \
        "refs/heads/reconcile/release-v*-to-develop")
      if [ "${#import_refs[@]}" -eq 1 ]; then head_ref="${import_refs[0]}"; fi
    fi
  fi
  if [[ "$head_ref" =~ $import_pattern ]]; then
    import_tag="v${BASH_REMATCH[1]}"
    import_push_args=()
    case "${GITHUB_EVENT_NAME:-}" in
      pull_request)
        if [ "$base_ref" != develop ] || [ "$release_pr_author" != litroc ] || \
            [ "${GITHUB_REPOSITORY:-}" != lightning-it/ansible-collection-supplementary ] || \
            [ "${GITHUB_HEAD_REPOSITORY:-}" != "${GITHUB_REPOSITORY:-}" ]; then
          echo "::error::Published baseline import requires the personal same-repository litroc PR to develop."
          exit 1
        fi
        ;;
      push)
        # These identity/ref facts are supplied only after the existing CI
        # associated-PR read proves the unique actual merged personal PR.
        if [ "$base_ref" != develop ] || [ "$release_pr_author" != litroc ] || \
            [ "${GITHUB_REPOSITORY:-}" != lightning-it/ansible-collection-supplementary ] || \
            [ "${GITHUB_HEAD_REPOSITORY:-}" != "${GITHUB_REPOSITORY:-}" ] || \
            [ -z "${BASE_SHA:-}" ] || [ -z "${HEAD_SHA:-}" ]; then
          echo "::error::Published baseline push lacks its actual merged personal PR binding."
          exit 1
        fi
        import_push_args=(--merged-push)
        ;;
      "") ;; # Offline proof only; no App or native review acceptance is asserted.
      *) echo "::error::Published baseline import requires a pull request or offline check."; exit 1 ;;
    esac
    import_develop="$(git rev-parse --verify refs/remotes/origin/develop^{commit})"
    if [ "${#import_push_args[@]}" -ne 0 ]; then
      import_develop="$BASE_SHA"
    elif [ -n "${BASE_SHA:-}" ] && [ "$BASE_SHA" != "$import_develop" ]; then
      echo "::error::Published baseline import has a stale protected Develop base."
      exit 1
    fi
    python3 scripts/verify_release_back_sync.py --published-baseline-import --check-worktree \
      "${import_push_args[@]}" \
      --develop-tip "$import_develop" \
      --release-sha "$(git rev-parse --verify refs/remotes/origin/main^{commit})" \
      --head-sha "${HEAD_SHA:-${PRE_COMMIT_TO_REF:-$(git rev-parse HEAD)}}" \
      --tag "$import_tag" --branch "$head_ref"
    is_published_baseline_import=true
    echo "Published release bytes verified; ordinary code and current-head human review requirements still apply."
  fi

  if [[ "$head_ref" == release/v* || "$head_ref" == backsync/release-* ]]; then
    is_release_branch=true
    is_trusted_release_branch=true
    case "${GITHUB_EVENT_NAME:-}" in
      pull_request)
        is_trusted_release_branch=false
        if [ "${GITHUB_HEAD_REPOSITORY:-}" = "${GITHUB_REPOSITORY:-}" ] && \
            [ -n "${GITHUB_REPOSITORY:-}" ] && \
            [ "$release_pr_author" = "lightning-it-release-automation[bot]" ] && \
            { \
              { [[ "$head_ref" == release/v* ]] && [ "$base_ref" = main ]; \
              } || \
              { [[ "$head_ref" == backsync/release-* ]] && [ "$base_ref" = develop ]; \
              }; \
            }; then
          is_trusted_release_branch=true
        fi
        ;;
      push)
        if [ "${GITHUB_HEAD_REPOSITORY:-}" != "${GITHUB_REPOSITORY:-}" ] || \
            [ -z "${GITHUB_REPOSITORY:-}" ] || \
            [ "$release_pr_author" != "lightning-it-release-automation[bot]" ] || \
            ! { \
          { [[ "$head_ref" == release/v* ]] && [ "$base_ref" = main ]; \
          } || \
          { [[ "$head_ref" == backsync/release-* ]] && [ "$base_ref" = develop ]; \
          }; \
        }; then
          is_trusted_release_branch=false
        fi
        ;;
      "")
        # Preserve deterministic local checks outside GitHub Actions.
        ;;
      *)
        is_trusted_release_branch=false
        ;;
    esac
  fi
  if [[ "$head_ref" == release/v* ]] && [ "$base_ref" = main ] && \
      git show "${HEAD_SHA:-HEAD}:changelogs/release-preparation.json" 2>/dev/null | \
        jq -e ".schema_version == 3 and .release_mode == \"normal\"" >/dev/null; then
    echo "::error::Schema3 normal preparation must enter Develop before Main promotion."
    exit 1
  fi
  if [[ "$head_ref" == release/v* ]] && [ "$base_ref" = develop ]; then
    # This is preparation ingress, not a Main release or published-baseline
    # import. Branch shape and an App login alone cannot qualify its contents.
    case "${GITHUB_EVENT_NAME:-}" in
      pull_request|push|"") ;;
      *) echo "::error::Unsupported normal preparation event."; exit 1 ;;
    esac
    if [ -n "${GITHUB_EVENT_NAME:-}" ]; then
      test "$release_pr_author" = "lightning-it-release-automation[bot]"
      test "${GITHUB_REPOSITORY:-}" = lightning-it/ansible-collection-supplementary
      test "${GITHUB_HEAD_REPOSITORY:-}" = "$GITHUB_REPOSITORY"
    fi
    test -n "${BASE_SHA:-}" && test -n "${HEAD_SHA:-}"
    normal_head="$HEAD_SHA"
    if [ "${GITHUB_EVENT_NAME:-}" = push ]; then
      read -r -a normal_parents <<<"$(git rev-list --parents -n 1 "$HEAD_SHA")"
      test "${#normal_parents[@]}" -eq 3
      test "${normal_parents[1]}" = "$BASE_SHA"
      test "$(git rev-parse "refs/remotes/origin/develop^{commit}")" = "$HEAD_SHA"
      normal_head="${normal_parents[2]}"
      test "$(git rev-parse "${HEAD_SHA}^{tree}")" = "$(git rev-parse "${normal_head}^{tree}")"
    else
      test "$(git rev-parse "refs/remotes/origin/develop^{commit}")" = "$BASE_SHA"
    fi
    normal_source="$(git rev-parse "refs/remotes/origin/main^{commit}")"
    python3 scripts/normal_release_proof.py preparation --root . \
      --base "$BASE_SHA" --head "$normal_head" --workflow-source "$normal_source" \
      --repository lightning-it/ansible-collection-supplementary --repository-id 1103407173 \
      --head-ref "$head_ref" --check-worktree
    is_trusted_release_branch=true
  fi
  if [[ "$head_ref" == develop && "$base_ref" == main ]]; then
    case "${GITHUB_EVENT_NAME:-}" in
      pull_request)
        if [ -n "${GITHUB_REPOSITORY:-}" ] && \
            [ "${GITHUB_HEAD_REPOSITORY:-}" = "${GITHUB_REPOSITORY:-}" ]; then
          is_release_promotion=true
        fi
        ;;
      push|"")
        is_release_promotion=true
        ;;
    esac
  fi

  if grep -E "$generated_re" <<<"$changed"; then
    if [ "$is_trusted_release_branch" != "true" ] && [ "$is_release_promotion" != "true" ] && \
        [ "$is_published_baseline_import" != "true" ]; then
      echo "::error::Generated changelog files require a trusted same-repository Release App release/back-sync PR"
      echo "::error::or a develop-to-main promotion. A release-shaped branch name alone grants no privilege."
      exit 1
    fi
  fi

  if [ "$is_release_branch" = "true" ]; then
    if [ "$is_trusted_release_branch" != "true" ]; then
      echo "::error::Release changelog handling requires the same-repository Release App author."
      exit 1
    fi
    echo "Release and release back-sync PRs manage generated changelog files."
    exit 0
  fi

  if has_label skip-changelog || has_label documentation || has_label ci || has_label tests; then
    echo "Changelog fragment requirement skipped by PR label."
    exit 0
  fi

  if [ "${REQUIRE_FRAGMENT:-true}" != "true" ]; then
    exit 0
  fi

  non_user_visible_re="^(\\.github/|\\.lit/|\\.releaserc|\\.pre-commit-config\\.yaml|\\.ansible-lint|"
  non_user_visible_re+="\\.yamllint|renovate|README\\.md|docs/|molecule/|tests/|scripts/|"
  non_user_visible_re+="CHANGELOG\\.(md|rst)|changelogs/config\\.yaml|"
  non_user_visible_re+="changelogs/changelog\\.yaml|changelogs/release-preparation\\.json$|"
  non_user_visible_re+="changelogs/fragments/|"
  non_user_visible_re+="package(-lock)?\\.json|AGENTS\\.md|CONTRIBUTING\\.md|SECURITY\\.md)"
  # .lit/ is reserved for repository governance metadata, alongside .github/.
  # This classifies release notes only; JSON, schema and security gates still apply.
  user_visible=""
  if user_visible="$(grep -Ev "$non_user_visible_re" <<<"$changed")"; then
    :
  else
    grep_status="$?"
    if [ "$grep_status" -ne 1 ]; then
      exit "$grep_status"
    fi
  fi

  if [ "$is_release_promotion" = "true" ] || [ "$is_published_baseline_import" = "true" ]; then
    promotion_metadata_re="^(galaxy\\.yml|CHANGELOG\\.(md|rst)|"
    promotion_metadata_re+="changelogs/(changelog|\\.plugin-cache)\\.yaml)$"
    user_visible=""
    if user_visible="$(grep -Ev "$non_user_visible_re|$promotion_metadata_re" <<<"$changed")"; then
      :
    else
      grep_status="$?"
      if [ "$grep_status" -ne 1 ]; then
        exit "$grep_status"
      fi
    fi
  fi

  if [ -z "$user_visible" ]; then
    echo "Only documentation, CI, tests, metadata, or changelog files changed."
    exit 0
  fi

  has_eligible_fragment=false
  while IFS= read -r fragment; do
    if ! grep -Eq "^changelogs/fragments/[^/]+\\.ya?ml$" <<<"$fragment"; then
      continue
    fi
    # Consumed published entries are deletions, never a new product-change note.
    # The import proof has already bound every surviving fragment to the head.
    if [ "$is_published_baseline_import" = "true" ] && \
        { [ ! -f "$fragment" ] || [ -L "$fragment" ]; }; then
      continue
    fi
    has_eligible_fragment=true
    break
  done <<<"$changed"
  if [ "$has_eligible_fragment" != "true" ]; then
    echo "::error::User-visible collection changes require a changelog fragment under changelogs/fragments/."
    exit 1
  fi
'
