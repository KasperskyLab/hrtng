# hrtng IDA plugin
hrtng IDA plugin is a collection of tools, ideas and experiments I've found interesting and useful in my reversing work.

Special thanks to following peoples for their great plugins were used as base for my work:
  * Hex-Rays SA [ida-sdk](https://github.com/HexRaysSA/ida-sdk) examples
  * Milan Bohacek, [hexrays_tools](https://github.com/nihilus/hexrays_tools) and [hexrays_hlight](https://hex-rays.com/contests_details/contest2016/hexlight/hexrays_hlight.py)
  * J.C. Roberts and Alexander Pick: [IDB2PAT](https://github.com/alexander-pick/idb2pat)
  * HexRaysDeob by [Rolf Rolles](https://hex-rays.com/blog/hex-rays-microcode-api-vs-obfuscating-compiler) and [Takahiro Haruyama](https://blogs.vmware.com/security/2019/02/defeating-compiler-level-obfuscations-used-in-apt10-malware.html)
  * Karthik Selvaraj [Krypton plugin](https://www.hex-rays.com/contests/2012/Krypton_2012_Hex-Rays_Contest.zip) 
  * Ali Rahbar, Ali Pezeshk and Elias Bachaalany [GraphSlick plugin](https://github.com/lallousx86/GraphSlick)
  * Markus Gaasedelen [AVX support for the Hex-Rays x64 Decompiler](https://github.com/gaasedelen/microavx)

The plugin requires Hex-Rays decompiler presence in your IDA installation.  
Only latest version of IDA is supported and evolves. However the plugin can be compiled with IDA SDK >= 7.3
New features and fixes added for the current IDA usually not well tested with old versions.

## Features of the plugin:
There is no one place in menu where all functionality of the plugin grouped together.
The plugin's menu items placed closer to logically related standard IDA & Hex-Rays decompiler functions.
Messages, menu items, popup windows and dialog boxes belong to this plugin are marked with "`[hrt]`" prefix.

### Automation
  * [Pull up comments from disasm to pseudocode view](doc/pull-cmt.md)
  * [Automatic renaming local and global variables, struct members](doc/var-auto-rename.md)
  * [Automatic enum substitution](doc/enum.md)
  * [COM helper](doc/com-helper.md)

### Interactive pseudocode transformation
  * [User interactive renaming/retyping assistance](doc/rename-recast.md)
  * [Assists with changing type of structure member or local/global variable](doc/recast.md)
  * [Invert "if" statement](doc/invert-if.md)
  * [reinterpret_cast](doc/reicast.md)
  * [Collapse selection](doc/collapse.md)
  * ["offsetof" convertor](doc/offsetof.md)

### Decryption
  * [Strings/data/const decryption](doc/decr.md)
  * [Build stack strings (optionally with decryption)](doc/stk-str.md)
  * [Build array strings (optionally with decryption)](doc/arr-str.md)
  * [Mass strings decryption](doc/appcall.md)

### Deal with obfuscated code
  * [Decompile obfuscated code](doc/deob.md)
  * [Hidden variable assignments](doc/hidden-assign.md)
  * [Scan for API names hashes](doc/api-hashes.md)
  * [Unflattening](doc/unflat.md)
  * [Microcode optimizers / "Magic" calls](doc/opt.md)

### Code recognition
  * [Microcode signatures](doc/msig.md)
  * [De-Inline - detection of inlined functions](doc/deinline.md)
  * [Create patterns (PAT) file from IDA database](doc/idb2pat.md)

### Type management assistance
  * [Create dummy structs](doc/cr_struc.md)
  * [Assist split gaps in structures](doc/struct-gaps.md)
  * [Union creation for a variable is reused with different types](doc/var-reuse.md)
  * [List of structures with given size, with given offset](doc/struct-sz-off.md)
  * [Assist in creation of new structure definitions](doc/struct-bld.md)
  * [Finds structures with same "shape" as is used](doc/struct-shape.md)
  * [Import user named functions prototypes into the local type library](doc/import_unf_types.md)
  * [~~New functionality in Structures view~~](doc/ex-unp-struc.md)
  * [IDC script for interactive merging types across multiple IDBs](bin/idc/merge_types.idc)

### Virtual/indirect calls assistance
  * [Virtual calls assistance](doc/virtual-calls.md)
  * [Jump to indirect call destination](doc/ijmp.md)
  * [Fix stack pointer for indirect call](doc/fix-stack.md)
 
### Function name and type
  * [Smart rename func](doc/rename-func.md)
  * [Convert function to __usercall, detect spoiled registers](doc/usercall.md)
  * [~~Set calling conventions bit closer to Go-lang~~](doc/golang.md)
  * [~~Remove function's return type converting it to void func(...)~~](doc/remove-ret-type.md)
  * [~~Remove function's argument~~](doc/remove-arg.md)

### IDA UI improvements
  * [Extended xrefs](doc/xrefs_ex.md)
  * [Matching brace highlight](doc/brace.md)
  * [Auto turn on 'Functions' window content synchronisation](doc/func-sync.md)
  * [Render markdown content of "IDA notepad" in a docked viewer](bin/plugins/notepad-md.py)

### Misk features
  * [Get API help](doc/zeal-api-help.md)
  * [AVX lifter](doc/avx.md)
  * [Dump strings, comments and names from the IDA database](doc/dump-strings.md)
  * [Offsets table creation](doc/offsets-tbl.md)
  * Print reversing progress percent on a proc renaming
  * [Recursively decompile callees](doc/recur-decomp.md)
  * [Refactoring (global Find and Replace)](doc/refactoring.md)
  * [~~Deal with structures with negative offsets or access based on offsets in a middle of structure~~](doc/neg-offs.md)

### Patching
  * [Patch custom area with NOPs](doc/patch-nops.md)
  * [Patch from debugger / Patch from file](doc/patch-dbg.md)
  * [Search & Patch](doc/search-n-patch.md)
  * [Create patched (DEC) file](doc/create_dec.md)

### IDA plugin developer help
  * [~~Microcode Explorer~~](doc/mcode-expl.md)
  * [Ctree graph](doc/ctree-graph.md)

## Media
### Reversing FinSpy
  * [securelist - Our secret ingredient for reverse engineering](https://securelist.com/hrtng-ida-pro-plugin/114780/) (EN)
  * [Хабр - Cекретный ингредиент для реверс-инжиниринга: как работает наш собственный опенсорс-плагин для IDA](https://habr.com/ru/companies/kaspersky/articles/865394/) (RU)
  * [Positive Hack Days Fest 2025 - Наш секретный ингредиент для реверс-инжиниринга](https://www.youtube.com/watch?v=Yxkg2zD7Ggw) (RU)
  * [Off-By-One 2025 - Speed up your reverse engineering with the hrtng plugin](https://www.youtube.com/watch?v=846wdb06k2g) (EN)
### Analyzing PlugX  
  * [SSTIC 2025 - Analysez des logiciels malveillants plus rapidement avec hrtng](https://www.sstic.org/2025/presentation/analysez_des_logiciels_malveillants_plus_rapidement_avec_hrtng/) (FR)

## Building

 * Clone hrtng together with [Crypto++® Library CMake](https://github.com/abdes/cryptopp-cmake) submodule. Or put manually downloaded `cryptopp-cmake` source code to `hrtng/src/cryptopp-cmake` folder.
 
```
cd src
git clone --recurse-submodules https://github.com/KasperskyLab/hrtng.git
```

 * Copy `IDA_DIR/plugins/hexrays_sdk/include/hexrays.hpp` file to the `include` directory of the IDA SDK. (Not necessary since IDA 9.0/8.5)
 * Edit `hrtng/src/CMakeLists.txt` file to set correct path and version of used IDA SDK. To build later with another SDK version you may change cmake's `IDASDK_VER` variable with using `cmake -D`, `ccmake` or `cmake-gui` tools.
 * Create build directory, go into it, configure and build cmake project
```
mkdir bld && cd bld
cmake <path-to/hrtng/src>
cmake --build . --config Release -j 4 --clean-first
```

 * On the first build attempt with IDA SDK before version 9.1 there will be compiling error looks like:

```
hrtng/src/deob.cpp:912:60: error: ‘class rangeset_t’ has no member named ‘as_rangevec’
     fc.create("tmpfc2", ranges.as_rangevec(), 0);//!!! add line into range.hpp, class rangeset_t: "const rangevec_t &as_rangevec() const { return bag; }"
```

 * To fix the error, edit `IDA_SDK/include/range.hpp` file, adding line with `as_rangevec` function implementation into `class rangeset_t` declaration as in the following example:

```
class rangeset_t
{
  rangevec_t bag;
  ...
  public:
  const rangevec_t &as_rangevec() const { return bag; }
  ...
};
```

 * Copy built binaries into `IDA_DIR/plugins` folder together with `apilist.txt` and `literal.txt` files from `hrtng/bin/plugins`
 * Profit

## License
This program is released under GPL v3 license

## Author
* Sergey.Belov at kaspersky.com

