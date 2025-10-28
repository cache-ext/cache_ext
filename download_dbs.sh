#!/bin/bash
set -eu -o pipefail

echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y rclone

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
# realpath is needed here due to an rclone quirk
DB_PATH=$(realpath $BASE_DIR/..)

BUCKET="cache-ext-artifact-data"

cd "$DB_PATH"

echo "Downloading databases from GCS (bucket: ${BUCKET})..."


echo "Downloading LevelDB database..."
rclone copy --progress --transfers 64 --checkers 64 --gcs-anonymous :gcs:${BUCKET}/leveldb "${DB_PATH}/leveldb/"
rclone check --progress --transfers 64 --checkers 64 --gcs-anonymous :gcs:${BUCKET}/leveldb "${DB_PATH}/leveldb/"

echo "Downloading Twitter trace metadata..."
rclone copy --progress --transfers 64 --checkers 64 --gcs-anonymous :gcs:${BUCKET}/twitter-traces "${DB_PATH}/twitter-traces/"
rclone check --progress --transfers 64 --checkers 64 --gcs-anonymous :gcs:${BUCKET}/twitter-traces "${DB_PATH}/twitter-traces/"

for cluster in 17 18 24 34 52; do
	echo "Downloading LevelDB Twitter cluster $cluster database..."
	rclone copy --progress --transfers 64 --checkers 64 --gcs-anonymous :gcs:${BUCKET}/leveldb_twitter_cluster${cluster}_db "${DB_PATH}/leveldb_twitter_cluster${cluster}_db/"
	rclone check --progress --transfers 64 --checkers 64 --gcs-anonymous :gcs:${BUCKET}/leveldb_twitter_cluster${cluster}_db "${DB_PATH}/leveldb_twitter_cluster${cluster}_db/"
done
