#!/usr/bin/env bash
sudo apt-get install python-pip python-dev rsync swig2.0
sudo apt-get install python-pyscard python-crypto libpcsclite-dev
sudo pip install pyscard
sudo pip install --upgrade humanfriendly wcwidth

# make sure /tmp is OK
# chmod 1777 /tmp
