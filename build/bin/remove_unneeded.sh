#!/bin/bash

# Sanity check: the file is created by the Dockerfile.
if [ ! -f /in-the-container ]; then
  echo "Don't run this outside the container!"
  exit 1
fi

# Array of basic tools needed by entrypoint and user_setup.
basicNeed=("bin/sh" "/bin/bash" "/usr/bin/coreutils")
libraries=()

function findDependencies()
{
    t=$1
    dependencies=$(ldd "${t}" \
        | grep -P "\.so\.\d?" \
        | sed -e '/^[^\t]/ d' \
        | sed -e 's/\t//' \
        | sed -e 's/.*=..//' \
        | sed -e 's/ (0.*)//')
}

# Get all that is needed by basicNeed
for i in "${basicNeed[@]}"; do
    findDependencies $i
    for library in $dependencies; do 
        if test -f "$library"; then
             if [[ ! " ${libraries[@]} " =~ " ${library} " ]]; then
                libraries+=( "$library" )
            fi
        fi
    done
done

# Recursively find all that is needed
loop=1
while [ "$loop" -eq 1 ]; do 
    loop=0
    for library in "${libraries[@]}"; do
        findDependencies $library
        for l in $dependencies; do
            if test -f "$l"; then
                if [[ ! " ${libraries[@]} " =~ " ${l} " ]]; then
                    libraries+=( "$l" )
                    loop=1
                fi
            fi
        done
    done
    ldd="${libraries[@]}"
done

# Recursively find all that is needed
loop=1
while [ "$loop" -eq 1 ]; do 
    loop=0
    for library in "${libraries[@]}"; do
        rlink=$(readlink "$library")

        for l in $rlink; do
            if [[ ! " ${libraries[@]} " =~ " ${l} " ]]; then
                loop=1
                libraries+=( "$l" )
            fi
        done
    done
    ldd="${libraries[@]}"
done

for i in "$@"; do
    for entry in "$i"/*; do
        remove=1
        for library in "${libraries[@]}"; do
            if [[ "$entry" == *"$library"* ]]; then
                remove=0
                break
            fi
        done
        if [ "$remove" -eq 1 ]; then
            rm -rf ${entry}
        fi
    done
done

# Remove un-needed tools. Leave only what is needed by user_setup and entrypoint
leave=(mkdir chown chmod rm whoami ls sh bash)
for entry in /bin/*; do
    remove=1
    for i in "${leave[@]}"; do
        if [[ "$entry" == *"$i" ]]; then
            remove=0
            break
        fi
    done
    if [ "$remove" -eq 1 ]; then
        rm -rf ${entry}
    fi
done

rm /in-the-container