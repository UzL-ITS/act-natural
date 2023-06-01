#!/bin/bash
PROJECT="btc-chat"
LIB="bit"
pip3 uninstall -y ${LIB}
bash update_coincurve_installation.sh
cd ${PROJECT}-${LIB}
python setup.py install --user
cd ..

