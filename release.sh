#!/bin/bash
# Make a simple release package
# author: aboudreault

# version is currently generated with the git revision
GITREV=`git log -n 1 | grep commit | cut -d' ' -f2`
VERSION="0~git${GITREV:0:8}"
NAME="dnds-$VERSION"
TAR="$NAME.tar.gz"

if [ ! -d udt4 ]
then
    git clone https://github.com/nicboul/udt4.git
fi

# Cleanup  if needed
if [ -d /var/tmp/$NAME ]
then
    echo "/var/tmp/$NAME exists, deleting it..."
    rm -rf /var/tmp/$NAME
fi

if [ -f /var/tmp/$TAR ]
then
    echo "/var/tmp/$TAR exists, deleting it..."
    rm /var/tmp/$TAR
fi

git archive --format=tar --prefix=$NAME/ HEAD | (cd /var/tmp/ && tar xf -)
$(cd udt4 && git archive --format=tar --prefix=udt4/ HEAD | (cd /var/tmp/$NAME && tar xf -))

$(cd /var/tmp && tar -zcf $TAR $NAME)

echo "Package source created: /var/tmp/$TAR"
