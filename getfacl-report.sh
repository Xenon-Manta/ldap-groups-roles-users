#!/bin/bash

echo "Recursive ACL Report"
echo "Starting directory: $(pwd)"
echo "========================================"

find . -print0 | while IFS= read -r -d '' item; do
    echo
    echo "----- $item -----"
    getfacl "$item"
done
