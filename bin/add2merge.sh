#!/bin/sh
sed -e 's/SetType/merge_type/g; s/add_struc_member/merge_struc_member/g; s/idc.idc/merge_types.idc/; /^static main(void)$/ { n; /^{$/ { s/{/{ init_merge_types();/; p;d;}};' $1 > m$1
