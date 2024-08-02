#/bin/sh
idapath=~/bin/ida
tmproot=/tmp
idaexe=idat
idaexe64=idat64

tmpdir=$(mktemp -d "$tmproot/idads_XXXXXX")
fname=$(basename "$1")
extension="${fname##*.}"
if test "$extension" = "i64"
then
  idaexe=$idaexe64
fi

cp "$1" "$tmpdir/$fname" || exit 1

$idapath/$idaexe -A -Sdump_strings.idc "$tmpdir/$fname"

rm -r "$tmpdir"
