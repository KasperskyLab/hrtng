## De-Inline - detection of inlined functions
Context menu *"Enable inlines"*, *"Disable inlines"*, *"Rename inline (N)"*, *"Create 'inline' from grouped nodes"*, *"Create 'inline' from selection"*

This experimental feature is inspired by ideas of [GraphSlick plugin](https://github.com/lallousx86/GraphSlick). Take a brief look at [problem description](https://github.com/nihilus/GraphSlick/raw/master/presentation/Shattering4.pdf). I've decided to implement another vision of the idea.

This implementation is based on comparing blocks by frequency dictionaries of Hex-Rays highly optimized micro-code and blocks relations. Such way is not sensitive to processor architecture, nor instruction ordering, nor even high level language was used - just a pure algorithm is in compare. Algorithm here is a set of high level constructions like arithmetic operations, loops and branches.  
There are still some restrictions for IDA versions older then 8.3: the inlined function should be a quite long to not produce false positives, one long block or few short basic blocks are good enough. And main limitation - inlined function must be aligned to basic blocks boundaries, if it shares some code in the first or last block with surrounding code such inlining will not be detected.  
For IDA 8.3 and later, in head, exit or single blocks, where just a part of the block should be inlined, the exact top level micro-instructions may be matched

How does it work:
  - Library-Inlines are loaded from files with "`.inl`" extension in "`$HOME/.idapro/inlines`" or "`%APPDATA%/Hex-Rays/IDA Pro/inlines`" folder at the plugin initialization phase.
  - De-Inliner takes control on latest possible phase of Hex-Rays decompilation when modification of microcode is still allowed and when microcode and control flow graph are well optimized.
  - For each basic block calculated frequency dictionary of microcode instruction opcodes together with their operands. Registers, global and stack variables considered as a same kind of variables. Indirect/direct calls are considered as a same type of calls. For calls makes sense to count arguments as individual instructions.
  - Then Library-Inlines are matched and marked for substitution (more details are below).
  - Finally all found Inlines (which is subgraph of matched blocks) cut out from microcode and replaced to "`call inline_name()`" helper.  
   Sometimes, if IDA kindly provide def/use chains, registers ~~and stack variables~~ defined somewhere outside Inline and used inside Inline become Inline arguments. Registers and stack variables defined inside Inline and used somewhere outside Inline become Inline returns.

De-Inliner technology allows IDA user to create a library of algorithms (i.e Inlines) which can be found across different binaries. For example C++ STL functions, encryption algorithms and so on. It may be used like a kind of high level signatures insensitive to platform or compiler was used for low-level code generation.

Inlines are shown in pseudocode like subroutine call.  
```
  crypto.rc4.set_key(ctx, key, keylen);
  stl.string.dtor(str);
```

There is no way "to enter" into Inline like into normal procedure call just because inline is integral part of currently decompiled procedure. To see what is hidden under Inline you can hover mouse over an inline call - and approximative contents of inline will be shown as a hint. Inline contents is not stored inside IDA's database and be re-decompiled on a fly as a set of blocks wrested from a context of the procedure.

To see whole procedure without inlines select from context menu - *"Disable inlines"*. *"Enable inlines"* - turn on them back.

To see and navigate to other Inlines with same name within current procedure press "Shift-X" or select menu entry *"Jump/Jump to xref Ex"*

Inlines are just created and not saved yet in the library can be renamed with *"Rename inline (N)"* context menu or with hotkey "N". To delete just created Inline - rename it with empty name.

![De-inlining on/off](deinline-on-off.gif)

There are four ways to create Library-Inline.
1) From Graph mode of disassembly view
	- In disassembly view go in Graph mode by pressing "Space" key
	- With Ctrl key and mouse wheel zoom out graph to see the piece of Graph to be Inline
	- With Ctrl key and left click select few nodes (blocks) of Graph.
	- Right click and select *"Group nodes"*, enter name of group.
	- Right click grouped node and select *"Create 'inline' from grouped nodes"*
	- Selections be verified (to be single entry and single exit), and then microcode for the selected blocks is generated.
	- In appeared window you can set name of Inline and see the microcode be used. Confirm it with "OK" or reject Inline creation with "Cancel" button.
	- Check created inline by decompiling current function - press "F5" or select menu *"View/Open subviews/Generate pseudocode"*, your inline should be seen as call in pseudocode.

![Create Inline from graph mode](deinline-graph.gif)

2) From plain disassembly view
	- In disassembly view select part of subroutine with Shift+Arrows or with Alt-L (menu *"Edit/Begin Selection"*) then right click and select *"Create 'inline' from selection"*
	- Hex-Rays microcode be generated for the selected area
	- In appeared window you can set name of Inline and validate the microcode be used for Inline. Confirm it with "OK" or reject with "Cancel" button.
	- Check created Inline by decompiling current function - press "F5" or select menu *"View/Open subviews/Generate pseudocode"*, your inline should be seen as call in pseudocode.

![Create Inline from disassembly view](deinline-disasm.gif)

3) From pseudocode view
	- In pseudocode view select part of subroutine with Shift+Arrows or with Alt-L (menu *"Edit/Begin Selection"*) then right click and select from the context menu *"Create 'inline' from selection"*
	- The plugin align selection to basic block boundaries and forces current subroutine re-decompilation
	- On re-decompilation the plugin tries to create inline from microcode belongs to selected area. Look at "Output window" messages if something went wrong.
	- Do not forget to rename just created Inline before saving database, it was created with name like `inline_40A97C_40AA20` where 40A97C and 40AA20 are addresses of selected range.

![Create Inline from pseudocode](deinline-pseudocode.gif)

4) From microcode view (starting from IDA 9.3) - currently preferred way to get correct inline boundaries
  - Open microcode window by "Ctrl-Shift-F8" hotkey or *"View/Open subview/Generate Microcode"* menu item
	- Raise maturity level up to `MMAT_GLBOPT2` by pressing ">" shortcut
  - Select part of micro-code with Shift+Arrows then right click and select *"Create 'inline' from selection"*
  - Check addresses in appeared dialog box, they must be aligned to basic-block or top level micro-instruction beginning addresses

Inlines Library is a folders hierarchy located in IDA's profile: "`~/.idapro/inlines`" in Linux and MacOS, "`C:\Users\%user%\AppData\Roaming\Hex-Rays\IDA Pro\inlines`" in Windows.  
For example "`~/.idapro/inlines/test1/test2/test.inl`" file should be seen in IDA as Inline call "`test1.test2.test();`".  
And reciprocal: if you are creating inline with dots in name: ex "`test1.test2.test`" - the folders hierarchy will be created.  
"`.inl`" file has a binary form but begins from text comment generated on creation - here are MD5 hash of source file and entry-exit addresses this inline has been created.

>📝 **Notes:** 
> - Just created Inline automatically validated - can it be found during decompilation. Inline should be seen as call in pseudocode. Message "inline %name% validated" in IDA's "Output window" confirms Inline is OK and will be saved to the library when IDA saves database - on exit, or by *"File/Save (Ctrl-W)"* menu.
> - Just created Inline has not been saved yet in the library might be renamed (or deleted) with "N" hotkey. After saving - inlines can be renamed by renaming files inside library folder.
> - Sometimes you can see Inline call in pseudocode, but there are not *"Disable inlines"*/*"Enable inlines"* appeared in context menu,  please force redecompilation by pressing F5 - *"Disable inlines"* should appears. This happens when Hex-Rays has not decompiled the current function but just took pseudocode from cache, at the same time the plugin believes this window containing pseudocode with inline was closed or switched to another proc without inlines.
