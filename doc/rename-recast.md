## User interactive renaming/retyping assistance

- Set type on rename : When user rename a local/global variable, struct member or a function, and new name is equal to known struct or proc typename this type pointer automatically will be applied to the variable. Then new name is ended with '_' and name is matched with any struct typename, this struct type will be applied to the renamed variable.
>⚠️ **Notes:** 
> - Struct member renaming callbacks is broken in IDA 8.4.
> - Name must exactly match typename. Case sensitive.
> - Be careful with short names like "exp" that is part of standard C library. Renaming var to such name will recast it to type "`double (__cdecl *exp)(double X)`"  
> - There is a many years long bug in IDA calling "`lxe_lvar_name_changed`" event callback with wrong `lvar_t*` argument. I've tried to make workaround for this bug, but it not always works well. The side effect of this bug: you have renamed or retyped one argument of func, but results are two arguments renaming/retyping. To deal with it: undo the operation with "Ctrl-Z", set simple name like "x" for the second argument, then rename first of them as you wish.
- Rename on set type : When user set named type to [Bad-Named](var-auto-rename.md) local variable this variable will be automatically renamed to typename.
- Rename VTBL method proc when VTBL struct member is renamed : When user renames member of structure which is VTBL description, corresponding proc is renamed too. 
- Inverse: Rename VTBL struct member when related proc is renamed by user.
- Change type of VTBL struct member when corresponding proc type is changed.
- Change return type of constructor proc when it renamed to `className::ctor` . When you are see a constructor proc you can rename it to something like `MyClass::ctor`, the return type of this proc be automatically changed to `MyClass*`
