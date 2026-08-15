#!/bin/sh

set -eu

source_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target_root=${1:-$source_root}
env_file=${2:-}
state_root=$(mktemp -d "$target_root/.xray-patched-deps.XXXXXX")
modfile="$state_root/xray.mod"
state_name=$(basename "$state_root")
relative_modfile="$state_name/xray.mod"

cp "$target_root/go.mod" "$modfile"
cp "$target_root/go.sum" "$state_root/xray.sum"

apply_module_patches() {
	module=$1
	patch_dir=$2
	name=$3

	(
		cd "$target_root"
		go mod download -modfile="$modfile" "$module"
	)
	module_dir=$(
		cd "$target_root"
		go list -modfile="$modfile" -m -f '{{.Dir}}' "$module"
	)
	patched_dir="$state_root/$name"

	if [ -z "$module_dir" ] || [ ! -d "$module_dir" ]; then
		echo "unable to locate module: $module" >&2
		exit 1
	fi

	mkdir -p "$patched_dir"
	cp -R "$module_dir/." "$patched_dir/"
	chmod -R u+w "$patched_dir"
	git -C "$patched_dir" init -q
	for patch in "$patch_dir"/*.patch; do
		[ -e "$patch" ] || continue
		if ! git -C "$patched_dir" apply --check --whitespace=error-all "$patch"; then
			echo "dependency patch does not apply: $patch" >&2
			exit 1
		fi
		git -C "$patched_dir" apply --whitespace=error-all "$patch"
	done

	go mod edit -modfile="$modfile" -replace="$module=./$state_name/$name"
}

apply_module_patches \
	github.com/apernet/quic-go \
	"$source_root/patches/quic-go" \
	quic-go

if [ -n "$env_file" ]; then
	printf 'GOFLAGS=-modfile=%s\n' "$relative_modfile" >> "$env_file"
else
	printf 'GOFLAGS=-modfile=%s\n' "$relative_modfile"
fi
