#!/usr/bin/env bash
set -ex

# checking that all release/fips/debug image are present in registry with the correct digest
for mode in release fips debug; do
    DIGEST=$(cat "output/${mode}.txt")
    IMAGE_NAME="fabric-envoy-$mode"
    if [ $IMAGE_NAME = "fabric-envoy-release" ]; then
        IMAGE_NAME="fabric-envoy"
        mode=""
    else
        mode="-$mode"
    fi
    cat >> data.yaml <<EOF
envoy${mode}:
    name: ${IMAGE_NAME}
    tag: ${TAG}
    multiarch_digest: ${DIGEST}
EOF
done

gomplate -f .datadog/campaigner/campaigner.yaml -d data.yaml > config.yaml
cat config.yaml
campaigns start --config-file config.yaml --env prod
