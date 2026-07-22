# Changelog

## [Unreleased]
### Added
### Changed
- Made "Refactoring" window smaller and dock friendly
- Autorename: ignore decompiler generated "nice" names
- Enable "Add VT" for types derived from external type-library
- Force renaming var under cursor on "Create dummy struct"
### Removed
### Fixed
- Autorename: fix `_vtbl` ban
- Autorename: avoid renaming vtbl to base class member
- One more workaround for "lxe_lvar_name_changed is sent for wrong variable" bug

## 3.9.108 - 2026-07-16
### Added
- IDA 9.4 support
- Automatically detect and set base class member inside derived class struct on VTBL-scan
### Changed
- "Recast item": do not deref pointer type in case if `var` is an argument of the function on recasting expressions like `*(type*)var`
- Reduced number of messages displayed on default logging level
- More info and debug messages on vtbl-scan
- "Rename func" - add wrapper suffix `_w` only for funcs
- "apilist.txt" for "APIhashes scan" is updated to conform Windows-11
### Removed
- "Invert "if" statement" obsolete for IDA 9.4
- "Fix stack pointer for indirect call" hope fixed in upstream
### Fixed
- Limit length of string duplicated to comment (IDA hangs on huge one)
- CRYPTOPP vs MSVS-2026 compatibility

## 3.9.105 - 2026-06-25
### Added
- deinline new modes:
	* split head and exit blocks (#45);
	* very short inlines are cut from inside a single block (#54)
	* inlines loading from work-folder too
	* keep compatibility with earlier inlines library
- Force update hex-rays's global xrefs cache on "Create MSIG file" in "All user named functions" mode, this reduces re-decompilation time when you need "Global xrefs" update;

### Changed
- Var reuse: manual mode if nothing found;
- Unflattening: 
	* assign variable pointer mode
	* message when unflattening is failed

### Removed
- deinline FIND_MATCHED_PATHS mode
- "Jump to visited indirect call... (Shift-J)" removed as duplicate, now jump by double-click/Enter-key on auto-comment

### Fixed
- Autorename: ban C++ mangled vftable names (#58)
- Fix unflatterer looping and register size issues
- Fix "Auto turn on 'Functions' window synchronisation" broken in IDA 9.3
- Fix crash on "Decompile obfuscated code Alt-F5", fix proc deletion and nav history;
- Fix "name-to-type" for union types;

## 3.8.94 - 2026-04-14
### Added
- Auto-comments:
	* @0xaddres -> name
	* display visited indirect calls

### Changed
- "Unite var reuse" does not create duplicate unions
- "Recast item" more usage patterns, including push call prototype to callee
- COM-helper and auto-name-and-type-propagation now work with indirect calls too
- "Refactoring" is case sensitive by default now. Refresh widgets after "Refactoring"
- Changed name-suffix on "Rename func"
- Force snippet-mode decompilation on "Decompile obfuscated code" when "Func regeneration" is unchecked ("stack frame too big" error workaround)

### Fixed
- 'apilist.txt' and 'literal.txt` files search paths (#55)
- Intel Mac builds for IDA 9.2/9.3 (only hcli package) (#51)
- Crash on change var type
- Cut struct size on last member recasting

## 3.8.88 - 2026-02-20
### Added
- IDA 9.3 support
- Experimental deobfuscation of indirect branch and call
- "Jump to visited indirect call ... (Shift-J)"

### Changed
- "Create dummy struct ..." - fixed-layout mode checkbox
- Auto select appropriate derived class VTBL is used by virtual call

### Fixed
- Fix Unflattening loses blocks (#47)

## 3.7.74 - 2025-11-25
### Changed
- Plain move idb+msig pair to another folder (store only name of msig file if it placed in the same dir as IDB)
- Strings and comments dumping improvement
- "magic" arithmetical calls accept any expressions
- Config options for:
	* maximum xref number for caller to callee argument names and types propagation (#43)
	* color of matched brace highlighting (#39)
- MicrocodeExplorer returns

### Fixed
- INTERR 50860 on unflattening
- Crash on single indirect jmp (#42)
- Adding VT structure fails if name contains special symbols (#41)
- check type name is unique for the case when user TIL is loaded
- IDA version check for notepad-md plugin (#40)

### Removed
- no more Intel Mac builds, sorry

## 3.7.69 - 2025-09-10
### Added
- IDA 9.2 support
- Thanks to ida-sdk open sourcing a few features derived from the SDK examples have been integrated:
	* Extended xrefs for registers or stack variables, decompiled representation of called functions or global variables
	* Hidden variable assignments
	* Invert "if" statement
	* Ctree graph
- Create PAT file from IDA database

### Changed
- Recognize var type shape significantly improved

## 2.7.63 - 2025-07-02
### Added
- Logging messages levels configurable by dialog and hrtng.cfg

### Changed
- Assist split gaps in structures for IDA9+ "fixed" structures
- Create dummy structs: convert allocation size to sizeof() like: newStructType* newStructType = malloc(sizeof(newStructType));
- C++ virtual tables: prefer typename_ against VT_addr for VTBL union member name
- Refactoring (global Find and Replace):
	* hot keys;
	* include unnamed functions into refactoring scope;
	* include user defined numeric forms;
	* don't show "Replace" field for deleted item;
	* display a line of multi-line comment;
- Auto renaming:
	* fix function argument renaming;
	* avoid using and setting name of overrun struct member;
	* renaming `*expr`;
	* ban `started` name

### Fixed
- Inlines saving/loading
- Jump to indirect call - find callback member destination
- Some context menu items have not been shown on cached pseudocode
- One more workaround for a function argument renaming bug

## 2.7.54 - 2025-05-23
### Added
- Refactoring (global Find and Replace)
- Markdown viewer for IDA notepad text
- Smart rename func
- Options dialog and config file (hrtng.cfg); disable autorename option
- Couple of examples of break through some custom obfuscation

### Changed
- Look for API hashes inside switch cases
- Improved type info propagation by auto-renamer

### Fixed
- Fix false auto-vtbl creation may destroys a good struct member
- Workaround for "ESC returns to wrong position"

## 2.5.41 - 2025-04-07
### Added
- Recursive decompiling
- IDC script for interactive merging types across multiple IDBs

### Changed
- C++ virtual calls handling remake:
	* auto scan and creation VTBL structures
	* auto union type for base and derived classes VTBLs
	* xref to proc on VTBL struct member instead comment
- Microcode signatures remake:
	* make two Strict & Relaxed signatures for a proc;
	* many names for a signature;
	* auto-load & auto-save the last used MSIG file;
	* Accept/Edit/Delete actions

### Fixed
- Some rough behavior has been polished
- Optimized very slow thing to be instant (search VTBL struct member by procname)

## 2.4.30 - 2025-03-10
### Added
- IDA 8.5/9.1 SDK build compatibility
- Import user named functions prototypes into the local type library
- Set-type-on-rename for functions
- Experimental support of ILP32 mode

### Changed
- Microcode signatures improvements

### Fixed
- Disable time-consuming operations during auto-analysis (fix #18)
- A few minor bugs fixed

## 2.3.25 - 2025-02-20
### Added
- "Magic" calls microcode optimizers

### Changed
- Improved var reuse recognition
- Autorenamer: ban `inited` name

### Fixed
- Fix "Add VT struct" to deal with bad/mangled/duplicate names (#13)
- Fix "the api help uses mangled name instead the real name" (#12)
- Autorenamer: `__get` --> `get` or `get_`
- Bugfix rare INTERR 50801 (#11)

## 2.2.21 - 2025-02-03
### Added
- Assist in creation of new structure definitions
- Finds structures with same "shape" as is used
- List of structures with given size, with given offset
- Union type for the stack var is reused with different types
- Print reversing progress percent to the output window on a proc renaming
- New functionality in Structures view
- Remove function's return type converting it to void func(...)
- Remove function's argument
- Deal with structures with negative offsets or access based on offsets in a middle of structure

## 1.1.19 - 2025-01-16
### Changed
- auto-renamer: call className::ctor_anything() provide name className
- "Create dummy struct" on variable or struct member will rename it
- One more suffix letter to dummy struct name

### Fixed
- Fix name and type changes of struct members for ida9
- Fix renaming VTBL/callbacks struct members on proc renaming

## 1.1.15 - 2024-12-23
### Changed
- Allow spaces in hex string is used as Key or IV on decryption

### Fixed
- Mangled names usage review
- Looking for apilist.txt & literal.txt in %IDAUSR% directory too
- Better displaying a const decryption results

## 1.1.11 - 2024-12-14
### Fixed
- Decryption engine small fixes and refactoring
- Rename virtual table member and type to be compatible with IDA names. Get/set vftable ea in addition to struct comment"@0xaddr"
- Fix negative 32bits API-hashes

## 1.1.8 - 2024-11-28
### Fixed
- Workaround for empty names processing appeared in ida9
- Decompile obfuscated code: slower but reliable way to del_items
- Debug diag & Docs


## 1.1.6 - 2024-11-20
### Changed
- Add 'dlopen' & 'dlsym' as a name source for autorenamer;

### Fixed
- Fix "new" on "Create dummy struct"
- Fix FunctionsToggleSync
- Bugfix jump to call dst

## 1.1.1 - 2024-10-11
### Added
- IDA9 support
- Detect spoiled registers on "Convert to __usercall"
- Dump IV on decrypt in CBC mode

## 1.0.0 - 2024-09-02
 - Initial release
