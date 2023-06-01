#!/bin/bash
PROJECT="btc-chat"
LIB="secp256k1"
BENCH="benchmark"
cd ${PROJECT}-${LIB}
if [ ! -f "./configure" ]
then
	bash autogen.sh
fi
if [ ! -f "./Makefile" ]
then
	bash configure
fi
make
cd ..
rm -rdf ${BENCH}
mkdir ${BENCH}
cd ${BENCH}
cp ../${PROJECT}-${LIB}/bench_aesni .
cp ../${PROJECT}-${LIB}/bench_ecdh .
cp ../${PROJECT}-${LIB}/bench_sha256 .
cp ../${PROJECT}-${LIB}/bench_nonceGen .
cp ../${PROJECT}-${LIB}/bench_ecdsa_sign .
ln -s ../${PROJECT}-${LIB}/.libs
cd ..

