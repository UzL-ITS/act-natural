#!/bin/bash
PROJECT="btc-chat"
LIB="coincurve"
pip3 uninstall -y ${LIB}
make -C ${PROJECT}-secp256k1/ clean 2> /dev/null
make -C ${PROJECT}-secp256k1/ distclean 2> /dev/null
cd ${PROJECT}-${LIB}
rm -rdf build/
python setup.py install --user
cd ..
#bash compile_libsecp256k1.sh

