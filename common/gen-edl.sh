#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedger8r --untrusted oe.edl
oeedger8r --trusted oe.edl

files+="oe_args.h "
files+="oe_t.h "
files+="oe_t.c "
files+="oe_u.c "
files+="oe_u.h "

license=`/bin/mktemp`

cat <<EOF > ${license}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

EOF

for i in ${files}
do
    tempfile=`/bin/mktemp`
    cp ${i} ${tempfile}
    cat ${license} > ${i}
    cat ${tempfile} >> ${i}
    rm -rf ${tempfile}
done

rm -r ${license}
