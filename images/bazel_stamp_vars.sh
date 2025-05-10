#!/usr/bin/env bash

git_rev="$(git rev-parse HEAD)"
if [[ $? != 0 ]];
then
    exit 0
fi

git_status="$(test -z "$(git status --porcelain)" && echo "clean" || echo "dirty")"
echo "GIT_REVISION ${git_rev}"
echo "GIT_STATUS ${git_status}"
