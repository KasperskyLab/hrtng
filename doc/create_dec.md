## Create DEC file
Menu *"File/Produce file/Create DEC file..."*

You can obtain decrypted/patched version of original file by *"File/Produce file/Create DEC file"* menu entry. The plugin makes copy of original file with "`.dec`" extension and apply to this file patches were applied to IDA database. To see list of patches click menu entry *"Edit/Patch program/Patched bytes (Ctrl-Alt-P)"*

The plugin exports IDC function "`create_dec`" that may be used for creating `.dec` files in batch mode.   
Ex: Create `create_dec.idc` file with following content:
```
#include <idc.idc>
static main()
{
  batch(1);
  create_dec();
  qexit(0);
}
```
And run this script by IDA with following parameters: `idat -A -Screate_dec.idc sample.idb`
