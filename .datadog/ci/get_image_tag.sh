#!/bin/bash
set -e

BUILD_PREFIX=alpha

function help {
      echo "Helper to get the current tag to be used with goreleaser"
      echo "Options:"
      echo "  -s, --strict: enforce a clean tree (e.g. for releasing)"
      echo "  -h, --help: show this help and exit"
}

STRICT="NO"
while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    -s|--strict)
      STRICT="YES"
      shift # past argument
      ;;
    -h|--help)
      help
      exit 0
      ;;
    *)    # unknown option
      echo "Unknown option $key"
      echo ""
      help
      exit 2
      ;;
  esac
done

commit=$(git rev-parse --short=8 --verify HEAD)
tag=$(git tag --points-at HEAD)

# goreleaser mandates the use of semver with no optional bypass
# Create some fake semver compliant tag now if not valid otherwise
# Note as part of semver https://semver.org/ identifiers must not include leading zeroes. Even
# though the short commit is compromised of alphanumeric characters, occasionally it will have
# only numeric characters and so we append a V to statisfy semver.

if  ! git diff --quiet; then # dirty working tree
      if [[ "$STRICT" == "YES" ]] ; then
            echo "Dirty tree while in strict mode, exiting"
            exit 1
      fi
      timestamp=$(date +%s)
      echo "v0.0.0-${BUILD_PREFIX}.v-${commit}.${timestamp}"
      exit 0
fi

if [ -z "$tag" ]
then
      # Increase previous tag with -rc or increase the release candidate if already one
      LATEST_TAG=$(git describe --tags --abbrev=0 || echo "")
      if [ -z "$LATEST_TAG" ]; then
            echo "v0.0.1-${BUILD_PREFIX}.v-$commit"
      elif [[ $LATEST_TAG =~ ^(v?[[:digit:]]+.[[:digit:]]+.)([[:digit:]]+)$ ]]; then
            echo "${BASH_REMATCH[1]}$((${BASH_REMATCH[2]} + 1))-${BUILD_PREFIX}.v-$commit"
      else
            echo "$LATEST_TAG-${BUILD_PREFIX}.v-$commit"
      fi
else
      echo "$tag"
fi