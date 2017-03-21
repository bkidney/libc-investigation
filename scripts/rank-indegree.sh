#!/bin/sh -

indegree=`gvpr -f indegree.gvpr $@`

echo "$indegree" | awk '{arr[$2]+=$1} END {for (i in arr) {print i, arr[i]}}' |sort -n -k 2
