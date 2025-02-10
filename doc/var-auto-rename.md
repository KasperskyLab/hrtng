## Automatic renaming local and global variables, struct members
The first thing I've seen very annoying when begins reverse a lot - I spend too much time for renaming variables which can be renamed automatically. So there is AutoRenamer has been implemented with following rules:
* Good-Name-Sources are:
	- user named global/local variable, struct member
	- user or library named arguments of called subroutine.
	- string literal, "helper" name
	- comment is not started from ';' letter
	- number in range: `1 < const_val < 0x80000000`
	- number in `enum` form
	- call to procedure with following name (`A`/`W` letters and additions like `_2` in the end of proc name are ignored):
		+ `GetLastError` produce name `err`
		+ function with name contains `get` substring. Example: `SomeClass::getSomething()` or `SomeClass::get_Something()` produce name: `Something`
		+ function with name contains `::ctor` substring. Example: `SomeClass::ctor_copy()` produce name: `SomeClass`
		+ `LoadLibrary(LibName)` and `GetModuleHandle(LibName)` produce name: `hLibName`
		+ `GetProcAddress(hMod, ProcName)` produce name: `ProcName`
		+ `strdup(Arg)`, `wcsdup(Arg)` produce name: `Arg`
		+ `????code_pointer(Arg)` and `??codePointer(Arg)` produce name: `Arg`
	- for reference prepended Good-Name like
		+ `&X_` produce name `X` (last '_' symbol stripped)
		+ `&X`  produce name `p_X` ('p_' inserted)
* Bad-Name-Sources are:
	- names like: `var_XX`, `arg_XX`, `aXX`, `vXX, vXa,` where `XX` one or two digits
	- CPU register names with optional numeric suffix (like `ecx0`)
	- struct member with name `VT` or name begins from `field_` or `fld_`
  - case sensitive names optionally prefixed with `lp` : `this`, `inited`, `result`, `Mem`, `Memory`, `Block`, `String`, `ProcName`, `ProcAddress`, `LibFileName`, `ModuleName`, `LibraryA`, `LibraryW`
	- in addition to above, for variables and call arguments only: `Str`, `Src`, `Dst`, `dwBytes`, `Flink`, `Blink`
* For the assignment operator like `A = B;` where one of side is a Good-Name-Source and another is unnamed (Bad-Name-Source) variable or struct member, bad-named part is renamed to `NameSource_XX` where `XX` is one or two digits
* Same for relation ops like `A == B`, `A < B`, etc 
* On renaming reference prepended variable or struct member like `&X`
	- `p_X` as new name became `X` (`p_` is stripped)
	- `X` as new name became `X_`  (last '_' symbol appended)
* `strcpy(A,B)`, `wcscpy(A,B)`, `lstrcpy(A,B)`, `qmemcpy(A,B)` considered as `A = B;` assignment
* `call(a1, a2, ...)` with typeinfo `func(p1, p2, ...)` considered as series of assignments `p1 = a1;` `p2 = a2;` etc...
	- bonus: if call argument has typeinfo and prototype of func has not: type and name of arguments will be propagated into func type (only if count of x-refs to such func less five to avoid renaming args in popular funcs like `memcpy`, `alloc`, etc).
* call of proc with name like `off_xxx` (usually appears at IAT in debugger session) is renamed to destination of this `off_xxx`
* wrapper (thunk) proc with only one call `subproc(...)` statement inside, is renamed to `subproc_`. ('_' symbol is appended to the name)
* every renaming has been happened is accompanied by a message in IDA Output Window
 
>📝 **Note:** sometimes AutoRenamer too aggressively propagates a wrong, meaningless name. Do not need to correct all of such wrong names, just rename one of them to correct and kill other with "N"-"Del"-"Enter". Then propagate new correct name by pressing "F5"
