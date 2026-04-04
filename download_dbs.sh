#!/bin/bash
set -eu -o pipefail

echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y zstd

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
# realpath is needed here due to an rclone quirk
DB_PATH=$(realpath $BASE_DIR/..)

BUCKET="cache-ext-artifact-data"
GCS_URL="https://storage.googleapis.com/${BUCKET}"

cd "$DB_PATH"

echo "Downloading databases from GCS (bucket: ${BUCKET})..."

download_and_extract() {
	local name=$1
	echo "Downloading ${name}.tar.zst..."
	if ! curl -fL --progress-bar "${GCS_URL}/${name}.tar.zst" -o "${name}.tar.zst"; then
		echo "ERROR: Failed to download ${name}.tar.zst"
		echo "The download URL may have changed. Please check for an updated version of this script at:"
		echo "  https://github.com/cache-ext/cache_ext"
		exit 1
	fi
	echo "Extracting ${name}.tar.zst..."
	tar --use-compress-program=zstd -xf "${name}.tar.zst"
	rm "${name}.tar.zst"
}

echo "Downloading LevelDB database..."
download_and_extract "leveldb"

echo "Downloading Twitter trace metadata..."
download_and_extract "twitter-traces"

for cluster in 17 18 24 34 52; do
	echo "Downloading LevelDB Twitter cluster $cluster database..."
	download_and_extract "leveldb_twitter_cluster${cluster}_db"
done
