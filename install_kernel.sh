#!/bin/bash
set -eu -o pipefail

# Install Linux build dependencies
echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential bc bison flex rsync libelf-dev \
			libssl-dev libncurses-dev dwarves clang lld \
			llvm python3 python3-pip

# Kernel build.py script dependencies
pip3 install yanniszark_common

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
LINUX_PATH="$BASE_DIR/linux"

cd "$LINUX_PATH"
if [[ ! -e "Makefile" ]]; then
    git submodule update --init --recursive
fi

# Clean previous builds
make distclean

echo "Configuring kernel..."
make olddefconfig

# Ignore 'yes' exit status
{ yes '' || true;} | make localmodconfig

scripts/config --set-str LOCALVERSION "-cache-ext"
scripts/config --set-str SYSTEM_TRUSTED_KEYS ''
scripts/config --set-str SYSTEM_REVOCATION_KEYS ''
scripts/config --enable CONFIG_BPF_SYSCALL
scripts/config --enable CONFIG_DEBUG_INFO_BTF

echo "Building and installing the kernel..."
echo "If prompted, hit enter to continue."
python3 build.py install --enable-mglru

echo "Building and installing libbpf..."
# Default location:
#	Library: /usr/local/lib64/libbpf.{a,so}
#	Headers: /usr/local/include/bpf
make -C tools/lib/bpf -j
sudo make -C tools/lib/bpf install

# Add ld.so.conf.d entry for libbpf
if [[ ! -e /etc/ld.so.conf.d/libbpf.conf ]]; then
	echo "/usr/local/lib64" | sudo tee /etc/ld.so.conf.d/libbpf.conf > /dev/null
	sudo ldconfig
	echo "Added /usr/local/lib64 to /etc/ld.so.conf.d/libbpf.conf"
else
	echo "/usr/local/lib64 already exists in /etc/ld.so.conf.d/libbpf.conf"
fi

echo "Building and install bpftool..."
make -C tools/bpf/bpftool -j
# Default location:
#	Binary: /usr/local/sbin/bpftool (version v7.3.0)
sudo make -C tools/bpf/bpftool install

if [[ -z "$(awk -F\' '/menuentry / {print $2}' /boot/grub/grub.cfg | grep -m 1 'Ubuntu, with Linux 6.6.8-cache-ext+')" ]]; then
	echo "Cannot find cache_ext kernel. Please install the kernel manually."
	exit 1
fi

echo "cache_ext kernel installed successfully. To boot into it, please run:"
echo -e "    sudo grub-reboot \"Advanced options for Ubuntu>Ubuntu, with Linux 6.6.8-cache-ext+\""
echo -e "    sudo reboot now"
