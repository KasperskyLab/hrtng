## Import user named functions prototypes into the local type library
Context menu *"Import user-named func types"* in the "Local Types" window

Usually when you take a new version of well reversed software or a module of soft that shares well reversed statically linked library
you need to export from well done IDB and apply to new binary:
 * any kind of signatures (FLIRT, MSIG, etc) 
 * type info as a "Create C header file" or "Dump typeinfo to IDC file"

But the copied typinfo after these steps is "detached" from the code, and you need manually assign types to recognized functions.

"Import user named functions prototypes" together with "set-type-on-rename" feature fill this gap. All you need to do just before exporting typeinfo into C or IDC file call
context menu *"Import user-named func types"* in the "Local Types" window. And then on applying signatures to a new binary this typeinfo will be tied to recognized functions.


