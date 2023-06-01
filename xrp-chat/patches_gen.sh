#!/bin/bash

PROJECT="xrp-chat"
LIBS="xrpl-py ecpy"
COMMIT_XRPL="b3130ca7a991984266b6b74e87ccafdb7490ca7e"
COMMIT_ECPY="8143d9ac017de0cb7f980bedaf56cefe6b4d9180"
PATCH_FOLDER="patches"

for lib in ${LIBS}
do
    REPO=${lib}
    PATCH_FOLDER_SUB=${PATCH_FOLDER}/${lib}
    mkdir -p ${PATCH_FOLDER_SUB}
    COMMIT1="$(git -C $REPO rev-parse HEAD)"
    case ${lib} in
        xrpl-py)    COMMIT0=${COMMIT_XRPL};;
        ecpy)       COMMIT0=${COMMIT_ECPY};;
    esac
    FILES=$(git -C ${REPO} diff --name-only ${COMMIT0} ${COMMIT1})
    git -C ${REPO} diff ${COMMIT0} ${COMMIT1} > ${PATCH_FOLDER}/${lib}.patch
    for file in ${FILES}
    do
        mkdir -p ${PATCH_FOLDER_SUB}/$(dirname ${file})
        git -C ${REPO} diff ${COMMIT0} ${COMMIT1} -- ${file} > ${PATCH_FOLDER_SUB}/${file}.patch
    done
done