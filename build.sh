#!/usr/bin/env bash
export JEKYLL_VERSION=3.8
sudo docker run --rm --volume="$PWD:/srv/jekyll" -it jekyll/jekyll:$JEKYLL_VERSION jekyll build

echo "Use 'gsutil rsync -d -r _site gs://<bucket>/stc-site' to publish"
