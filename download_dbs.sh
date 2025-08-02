#!/bin/bash
set -eu -o pipefail

echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y rclone

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
# realpath is needed here due to an rclone quirk
DB_PATH=$(realpath $BASE_DIR/..)

cd $DB_PATH

echo "Configuring rclone B2 backend..."
RCLONE_CONFIG_FILE=$(rclone config file | tail -n 1)

if ! rclone config show b2 &>/dev/null; then
	read -p "Enter your B2 Account ID: " B2_ACCOUNT_ID
	read -s -p "Enter your B2 Account Key: " B2_ACCOUNT_KEY
	echo

	# Manually append the config entry to the rclone config file
	cat <<EOF >> "$RCLONE_CONFIG_FILE"
[b2]
type = b2
account = $B2_ACCOUNT_ID
key = $B2_ACCOUNT_KEY
EOF
else
	echo "B2 config already present in $RCLONE_CONFIG_FILE, skipping configuration."
fi

echo "Downloading databases from B2..."

echo "Downloading LevelDB database..."
rclone copy --progress --transfers 64 --checkers 64 b2:leveldb "${DB_PATH}/leveldb/"
rclone check --progress --transfers 64 --checkers 64 b2:leveldb "${DB_PATH}/leveldb/"

echo "Downloading Twitter trace metadata..."
rclone copy --progress --transfers 64 --checkers 64 b2:twitter-traces "${DB_PATH}/twitter-traces/"
rclone check --progress --transfers 64 --checkers 64 b2:twitter-traces "${DB_PATH}/twitter-traces/"

for cluster in 17 18 24 34 52; do
	echo "Downloading LevelDB Twitter cluster $cluster database..."
	rclone copy --progress --transfers 64 --checkers 64 b2:leveldb-twitter-cluster${cluster}-db "${DB_PATH}/leveldb_twitter_cluster${cluster}_db/"
	rclone check --progress --transfers 64 --checkers 64 b2:leveldb-twitter-cluster${cluster}-db "${DB_PATH}/leveldb_twitter_cluster${cluster}_db/"
done
