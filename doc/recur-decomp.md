## Recursively decompile callees
Menu *"View/Open subviews/Decompile recursively (Shift-Alt-F5)"*

This experimental feature have the intention to apply multiple [microcode signatures](msig.md) at once.
Type info is delivered by MSIGs in conjunction with [Import-function-prototype](import_unf_types.md) feature,
is propagated across the call graph in such kind of decompilation.
The top level function's MSIG is recognized better when the callee functions have a well recognized type.  
As well this decompilation mode can be used for type propagation across the call graph without MSIGs loaded.

How does it work:
 - The current function is decompiled for the first time. With using decompilation cache or not depending on has the function user defined type.
 - The function is decompiled again if the function type is changed by the first decompilation step (by the decompiler itself or by matching microcode signature)
 - The body of the function is scanned for call's destinations (as well as direct, indirect and virtual calls)
 - All the listed steps are repeated for each callee
 - The function is decompiled again if any global variable type or any function type has been changed during the previous step

Then recursively decompile is done the following message is appeared in Output window
```
[hrt] 1000092C0: on recursive decompile 4125 types changed by decompiling 1111 procs
```

Try to run recursively decompile again on the same proc.
```
[hrt] 1000092C0: on recursive decompile 250 types changed by decompiling 1111 procs
```

And again
```
[hrt] 1000092C0: on recursive decompile 56 types changed by decompiling 1111 procs
```

And again
```
[hrt] 1000092C0: on recursive decompile 30 types changed by decompiling 1111 procs
```

Because of any function in a call graph may be decompiled up to three times or only once if some func type is changed or not during decompilation, the next Recursively Decompile pass faster then previous.


