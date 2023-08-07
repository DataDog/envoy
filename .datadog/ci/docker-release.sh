#!/usr/bin/env bash

function help {
    echo "Build a new version of the envoy docker image"
    echo "Compilation tarballs are expected to be available at the specific path:"
    echo "  build_envoy/release-$COMPILE_MODE-$ARCH.tar.zst"
    usage
}

function usage {
    echo "Usage: "
    echo "  -m, --mode: which image to deliver. Valid options are currently [release, debug, fips]. Defaults to 'release'"
    echo "  -t, --tag: tag of the image (mandatory)"
    echo "  -r, --replication: replication tag to set (build, staging or prod). Defaults to 'build'"
    echo "  -a, --arch: architectures to deliver for. Defaults to (amd64 arm64)"
    echo "  -d, --dockerfile: Dockerfile to use. Defaults to '.datadog/images/Dockerfile-build'"
    echo "  --registry: registry to use (can be extended based on the mode if not release). Defaults to 'registry.ddbuild.io/fabric-envoy'"
    echo "  -p, --push: (deprecated) the manifest and images are directly pushed by default"
    echo "  -l, --load: (Not supported in CI) If set, images and manifests will only be loaded into a docker daemon"
    echo "  --no-sign: if set, the images will not be signed (useful if ddsign is not installed on the machine)"
    echo "  -h, --help: show this help and exit"
}

function error {
    echo "$1"
    echo ""
    usage
    exit 2
}

set -euo pipefail

MODE="release"
TAG=""
TARGET="build"
ARCHS=()
ACTION="--push"
DOCKERFILE=".datadog/images/Dockerfile-build"
BASE_REGISTRY="registry.ddbuild.io/fabric-envoy"
BASE_IMAGE="registry.ddbuild.io/images/base/gbi-ubuntu_2204:release"
SKIP_SIGN=false
IS_FIPS="false"

while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    -m|--mode)
      MODE="$2"
      shift
      shift # past argument
      ;;
    -t|--tag)
      TAG="$2"
      shift
      shift # past argument
      ;;
    -r|--replication)
      TARGET="$2"
      shift
      shift # past argument
      ;;
    -a|--arch)
      ARCHS+=("$2")
      shift
      shift # past argument
      ;;
    -p|--push)
      ACTION="--push"
      shift
      ;;
    -l|--load)
      ACTION="--load"
      shift
      ;;
    -d|--dockerfile)
      DOCKERFILE="$2"
      shift
      shift # past argument
      ;;
    --registry)
      BASE_REGISTRY="$2"
      shift
      shift # past argument
      ;;
    --no-sign)
      SKIP_SIGN=true
      shift
      ;;
    -h|--help)
      help
      exit 0
      ;;
    *)    # unknown option
      error "Unknown option $key"
      ;;
  esac
done

# Validate tag. Cannot be empty as this would be interpreted as latest
if [ -z "$TAG" ]; then
    error "No tag provided"
fi

# Validate and remap target to avoid propagating the specific "build" target naming elsewhere
case "$TARGET" in
    "build")
        TARGET="dd-registries-internal-only"
        ;;
    "staging"|"prod")
        ;;
    *)
        error "Invalid target provided"
        ;;
esac

if [ ${#ARCHS[@]} -eq 0 ]; then
    ARCHS=(amd64 arm64)
fi

PLATFORMS=()
for ARCH in ${ARCHS[@]}; do
    PLATFORMS+=("linux/$ARCH")
done
PLATFORMS=$(IFS=, ; echo "${PLATFORMS[*]}")

# Only used for the envoy dockerfile
case "$MODE" in
    "release")
        REGISTRY="$BASE_REGISTRY"
        BINARY_PREFIX=""
        COMPILE_MODE="opt"
        ;;
    "debug")
        REGISTRY="$BASE_REGISTRY-debug"
        BINARY_PREFIX="dbg/"
        COMPILE_MODE="opt"
        ;;
    "fips")
        REGISTRY="$BASE_REGISTRY-fips"
        BINARY_PREFIX=""
        COMPILE_MODE="opt-fips"
        IS_FIPS="true"
        BASE_IMAGE="registry.ddbuild.io/images/base/gbi-ubuntu_2204-fips:release"
        ;;
    *)
        error "Unknown mode '$MODE'"
        ;;
esac

METADATA_FILE=$(mktemp)
docker buildx build . -f $DOCKERFILE --platform $PLATFORMS \
    -t $REGISTRY:$TAG --label target=$TARGET $ACTION \
    --build-arg ENVOY_BINARY_PREFIX=$BINARY_PREFIX --build-arg COMPILE_MODE=$COMPILE_MODE --build-arg BASE_IMAGE=$BASE_IMAGE \
    --label is_fips=$IS_FIPS \
    --metadata-file ${METADATA_FILE} --iidfile "digest.txt"

if [ "$SKIP_SIGN" != true ]; then
  ddsign sign $REGISTRY:$TAG --docker-metadata-file ${METADATA_FILE}
fi

mkdir -p output
cat digest.txt > output/${MODE}.txt
