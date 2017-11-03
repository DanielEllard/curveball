#!/usr/bin/env bash

INDEXFILE="/home/awjacks/web_content/index.html"

copy_index_html() {
    dirspec="$1"
    if [ -d ${dirspec} ]; then 
	echo "Copying ${INDEXFILE} to ${dirspec}"
	cp ${INDEXFILE} ${dirspec}
    fi
}

index_html_exists() {
    dirspec="$1"    
    if [ -e ${dirspec}/index.html ]; then
	return 1
    else
	return 0
    fi
}

if [ ! -e "${INDEXFILE}" ]; then
    echo "ERROR: ${INDEXFILE} does not exist"
    return 0
fi

for dirname in $@; do
    if [ -d ${dirname} ]; then
	# echo ${dirname} "is a directory"
	index_html_exists ${dirname}
	if [ $? -eq 1  ]; then
	    echo "${dirname}/index.html exists, skipping..."
	else
	    copy_index_html ${dirname}
	fi
    else
        echo ${dirname} "is a not a directory"
    fi
done
    