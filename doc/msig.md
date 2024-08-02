## Microcode signatures
Context menu *"Create MSIG for the function"*  
Menu *"File/Produce file/Create MSIG file..."*, *"File/Load file/MSIG file..."*

Ida's flirt signatures depends a lot on a processor architecture and fails on an obfuscated code. Microcode signatures have no such limitation. They are applied on microcode during latest decompilation stage when obfuscations possible gone.

You can create msig one by one with selecting *"Create MSIG for the function"* in pseudocode context menu and then save them all by calling menu *"File/Produce file/Create MSIG file..."*. Or create and save msigs for all user-named function at once.

![Creating microcode signatures](msig-save.gif)

Load signatures with *"File/Load file/MSIG file..."* "`.msig`" file is editable text file where each line is MD5 hash of the source procedure microcode and signature name.

When on a procedure decompilation microcode matches the signature comment is appeared it the first pseudocode line.
```
// The function matches 'msig-name'
```

![Applying microcode signatures](msig-apply.gif)
