#!/bin/bash

PROJECT="btc-chat"
LIBS="bit coincurve secp256k1"
COMMIT_SEC="4c3ba88c3a869ae3f45990286c79860539a5bff8"
COMMIT_COIN="0bb42ce2d97e7ded8181b10e6a96122865c9854f"
COMMIT_BIT="776f97ae7f9b3f05157113abc913eb141b2817ee"
PATCH_FOLDER="patches"

for lib in $LIBS
do
    REPO=${PROJECT}-${lib}
    PATCH_FOLDER_SUB=${PATCH_FOLDER}/${lib}
    mkdir -p $PATCH_FOLDER_SUB
    COMMIT1="$(git -C $REPO rev-parse HEAD)"
    case $lib in
        bit)        COMMIT0=$COMMIT_BIT;;
        coincurve)  COMMIT0=$COMMIT_COIN;;
        secp256k1)  COMMIT0=$COMMIT_SEC;;
    esac
    FILES=$(git -C $REPO diff --name-only $COMMIT0 $COMMIT1)
    git -C $REPO diff $COMMIT0 $COMMIT1 > ${PATCH_FOLDER}/${lib}.patch
    for file in $FILES
    do
        mkdir -p ${PATCH_FOLDER_SUB}/$(dirname $file)
        git -C $REPO diff $COMMIT0 $COMMIT1 -- $file > ${PATCH_FOLDER_SUB}/${file}.patch
    done
done
