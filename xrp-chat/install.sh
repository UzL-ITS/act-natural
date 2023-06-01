#!/bin/bash

cd -- "$(dirname "$0")"
for folder in ecpy xrpl-py
do
    cd $folder
    pip install --user .
    cd ..
done
