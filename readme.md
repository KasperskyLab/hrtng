# hrtng IDA plugin
hrtng IDA plugin is a collection of tools, ideas and experiments from different sources I've found interesting and useful in my reversing work.

A practical guide to the reverse of a complex malware using the example of dissecting a FinSpy module wih help of hrtng IDA plagin on [securelist](https://securelist.com/hrtng-ida-pro-plugin/)

There is no one place in menu where all functionality of the plugin grouped together. hrtng menu items placed closer to logically related standard IDA & Hex-Rays decompiler functions. Messages, menu items, popup windows and dialog boxes belong to this plugin are marked with "`[hrt]`" prefix.  

The plugin requires Hex-Rays decompiler presence in your IDA installation. The plugin can be compiled with IDA SDK >= 7.3 but not well tested with old versions.

Special thanks to following peoples for their great plugins were used as base for my work:
  * Milan Bohacek, [hexrays_tools](https://github.com/nihilus/hexrays_tools) and [hexrays_hlight](https://hex-rays.com/contests_details/contest2016/hexlight/hexrays_hlight.py)
  * HexRaysDeob by [Rolf Rolles](https://hex-rays.com/blog/hex-rays-microcode-api-vs-obfuscating-compiler) and [Takahiro Haruyama](https://blogs.vmware.com/security/2019/02/defeating-compiler-level-obfuscations-used-in-apt10-malware.html)
  * Karthik Selvaraj [Krypton plugin](https://www.hex-rays.com/contests/2012/Krypton_2012_Hex-Rays_Contest.zip) 
  * Ali Rahbar, Ali Pezeshk and Elias Bachaalany [GraphSlick plugin](https://github.com/lallousx86/GraphSlick)
  * Markus Gaasedelen [AVX support for the Hex-Rays x64 Decompiler](https://github.com/gaasedelen/microavx)

## Features of the plugin:

### Automation
  * [Pull up comments from disasm to pseudocode view](doc/pull-cmt.md)
  * [Automatic renaming local and global variables, struct members](doc/var-auto-rename.md)
  * [Automatic enum substitution](doc/enum.md)
  * [COM helper](doc/com-helper.md)

### Interactive pseudocode transformation
  * [User interactive renaming/retyping assistance](doc/rename-recast.md)
  * [Assists with changing type of structure member or local/global variable](doc/recast.md)
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
  * [Scan for API names hashes](doc/api-hashes.md)
  * [Unflattening](doc/unflat.md)

### Code recognition
  * [Microcode signatures](doc/msig.md)
  * [De-Inline - detection of inlined functions](doc/deinline.md)

### Structures assistance
  * [Create dummy structs](doc/cr_struc.md)
  * [Assist split gaps in structures](doc/struct-gaps.md)

### Virtual/indirect calls assistance
  * [Virtual calls assistance](doc/virtual-calls.md)
  * [Jump to indirect call destination](doc/ijmp.md)
  * [Fix stack pointer for indirect call](doc/fix-stack.md)

### IDA UI improvements
  * [Extended xrefs](doc/xrefs_ex.md)
  * [Matching brace highlight](doc/brace.md)
  * [Auto turn on 'Functions' window content synchronisation](doc/func-sync.md)

### Misk features
  * [Get API help](doc/zeal-api-help.md)
  * [AVX lifter](doc/avx.md)
  * [Dump strings, comments and names from the IDA database](doc/dump-strings.md)
  * [Offsets table creation](doc/offsets-tbl.md)
  * [Convert function to __usercall, detect spoiled registers](doc/usercall.md)
  * [Set calling conventions bit closer to Go-lang](doc/golang.md)

### Patching
  * [Patch custom area with NOPs](doc/patch-nops.md)
  * [Patch from debugger / Patch from file](doc/patch-dbg.md)
  * [Search & Patch](doc/search-n-patch.md)
  * [Create patched (DEC) file](doc/create_dec.md)

### IDA plugin developer help
  * [Microcode Explorer](doc/mcode-expl.md)

## Building

 * Clone or download [Crypto++® Library CMake](https://github.com/abdes/cryptopp-cmake) source code to `hrtng/src/cryptopp-cmake` folder.
 
```
cd src
git clone https://github.com/abdes/cryptopp-cmake
```

 * Copy `IDA_DIR/plugins/hexrays_sdk/include/hexrays.hpp` file to the `include` directory of the IDA SDK. (Not necessary for IDA 9.0)
 * Edit `hrtng/src/CMakeLists.txt` file to set correct path and version of used IDA SDK. To build later with another SDK version you may change cmake's `IDASDK_VER` variable with using `cmake -D`, `ccmake` or `cmake-gui` tools.
 * Create build directory, go into it, configure and build cmake project
```
mkdir bld && cd bld
cmake <path-to/hrtng/src>
cmake --build . --config Release -j 4 --clean-first
```

 * On the first build attempt there will be compiling error looks like:

```
hrtng/src/deob.cpp:912:60: error: ‘class rangeset_t’ has no member named ‘getbag’
     fc.create("tmpfc2", ranges.getbag(), 0);//!!! add line into range.hpp, class rangeset_t: "const rangevec_t &getbag() const { return bag; }"
```

 * To fix the error, edit `IDA_SDK/include/range.hpp` file, adding line with `getbag` function implementation into `class rangeset_t` declaration as in the following example:

```
class rangeset_t
{
  rangevec_t bag;
  ...
  public:
  const rangevec_t &getbag() const { return bag; }
  ...
};
```

 * Copy built binaries into `IDA_DIR/plugins` folder togeter with `apilist.txt` and `literal.txt` files from `hrtng/bin/plugins`
 * Profit

## License
This program is released under GPL v3 license

## Authors
* Sergey.Belov at kaspersky.com

