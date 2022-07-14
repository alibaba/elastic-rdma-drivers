#!/bin/bash

name=`basename $0`
cd `dirname $0`
scripts_dir=`pwd`

# Execute command w/ echo and exit if it fail
ex()
{
        echo "$@"
        eval $@
	if [ "$?" != "0" ]; then
		echo "$@   FAILED"
	        exit 1
	fi
}

if [ ! -d $scripts_dir/patches ]; then
	echo "scripts/patches directory does not exist"
	exit 1;
fi

ex cd $scripts_dir/../rdma-core

ex "git am $scripts_dir/patches/*.patch"
