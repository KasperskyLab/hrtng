## Create dummy structs
*Menu "Edit/Structs/Create dummy struct...(Shift-S)"*

When you want create new structure with knows size but doesn't know content you can press "Shift-S" and enter size of new structure.  
If cursor is currently placed on a number in pseudocode view - the number will be used as struct size.   
If this number is an argument of call contains "alloc" or "new" substring in a function name, and this call is a part of assignment - the variable or struct member on left side of the assignment will be renamed and recasted to created struct type pointer.   
As well, if cursor is currently placed on variable or struct member it will be renamed and recasted.

Name of struct is auto-suggested. There is an option to create "empty" structure (with only last field) or create structure filled by DWORDs (or QWORDS for 64bit). Structures with size over 10kB are created as "empty" by default.

![Create struct](cr_struc-add_vt.gif)
