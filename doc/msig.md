## Microcode signatures
Context menu *"Create MSIG for the function"*  
Menu *"File/Produce file/Create MSIG file..."*, *"File/Load file/MSIG file..."*

Ida's flirt signatures depends a lot on a processor architecture and fails on an obfuscated code. Microcode signatures have no such limitation.
It is applied on microcode during latest decompilation stage when obfuscations possible gone.

You can create msig one by one with selecting *"Create MSIG for the function"* in pseudocode context menu and then save them all by menu *"File/Produce file/Create MSIG file..."*. 
Or create and save msigs for all user-named function at once. 
There are options in the "Create MSIG file" dialog:
 * Minimal signature lenghth - is a minimal length in bytes of the procedure body, and the same time a minimal length on microcode is used to build signature. This value is also used for a single signature creation.
 * Skip indirect call arguments - check this box in case if your binary has a lot of indirect calls, which arguments often incorrectly recognized until reverser manually "set call type". The same option have to be set on microcode signature loading to switch signature searching engine to the right mode.

![Creating microcode signatures](msig-save.gif)

Load signatures with *"File/Load file/MSIG file..."* Multiple `.msig` files may be loaded.

"`.msig`" file is editable text file where each line is MD5 hash of the microcode and the signature name.

The comment is appeared it the first pseudocode line when a matcing signature has been found. And the procedure is renamed (but a new name may appears just after repeating `F5` key press)
```
// The function matches 'msig-name'
```

![Applying microcode signatures](msig-apply.gif)
