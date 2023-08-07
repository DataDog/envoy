# Datadog envoy private fork

This fork has been created to allow implementation of additional filters or resources in envoy. As a private fork it is not automatically synchronized with upstream.

**dd-main is the main branch used for datadog**

## How to sync with upstream tag for delivery
```
<!-- Checkout `main`, our copy of upstream's main branch -->
git checkout main
git pull

git remote add upstream https://github.com/envoyproxy/envoy
<!-- Pull from upstream latest main and tags -->
git pull upstream main
git fetch --tags upstream

<!-- Push main to the repo. We normally don't commit against this branch -->
git push origin main
git push --tags

<!-- Merge a specific tag into datadog main and push it -->
git checkout dd-main
git rebase {tag}
git tag {tag}-dd
git push
git push origin {tag}-dd
```

## Actions
Envoy upstream repo uses options github actions for most of its CI as well as repo maintenance.
Those actions are still set on `dd-main` but actions are globally disabled on the repository.

## CI/CD 
On each PR, envoy tests will be run:
 * there are currently failed tests due to missing ipv6 supports on gitlab runners.
 * tests are therefore allowed to fail, and you should review which ones are failed
 * manual build and release jobs are also created to allow testing the code in staging

On merge:
 * an image will be delivered for the default envoy registry, and replicated to staging

On tag:
 * if the tag does not match `.*-dd`, nothing will happen (this is to not trigger CI on upstream sync)
 * if the tag does match, a new version will be released for all three versions: `envoy`, `envoy-debug` and `envoy-fips`, each with both amd64 and arm64 support

To update the CI runner image:
 * Update the Dockerfile in `.datadog/ci/Dockerfile-builder`
 * Run the manual CI job `deliver-ci`
 * Update the image tag in CI variable `CI_IMAGE` in `.gitlab-ci.yml`
