## Microcode optimizers

### "Magic" call replacement. 
C++ optimizing compiler may reuse code of simple class methods like `member_t* CMyClass::GetMember() { return &member;}` for different classes.
So in a usual way the reverser should create union for the classes were used to call this method and apply it to the `this` argument of the call and one more union for all possible returning types.  
However the such a simply call might be replaced to micro-code that directly access class member, so type casting of argument and return value will be automatically resolved by the decompiler.  
You just need to set right size of returning type and argument (like `_QWORD` or `_DWORD`) and rename the destination proc of the call to the "magic" name and the plugin does code substitution automatically.

>⚠️ **Warning:** Currently these "magic" call optimizers do not care about registers were spoiled by the original call and stack balance in case of __stdcall. So please remember it before using.

For the following calls where `NN` is a number in hex and `x` is an any expression:
 * `LDX_0xNN(x)` will be replaced to `[x + NN]`. The size of memory accessed by new expression will be equal to the size was used in original call expression.
 * `RET_0xNN()`  ==> `NN`
 * `ADD_0xNN(x)` replaced to `x + NN`
 * `SUB_0xNN(x)` ==> `x - NN`
 * `AND_0xNN(x)` ==> `x & NN`
 * `OR__0xNN(x)` ==> `x | NN`
 * `XOR_0xNN(x)` ==> `x ^ NN`

One more optimizer watches calls that do simple arithmetic operation and receive two numbers as arguments then replaces call expression to the result of arithmetic operation.
Size of resulting number is set equal to the returning type size of original call.
 * `ADD(n1, n2)` ==> result of `n1 + n2` 
 * `SUB(n1, n2)` ==> result of `n1 - n2` 
 * `AND(n1, n2)` ==> result of `n1 & n2` 
 * `OR_(n1, n2)` ==> result of `n1 | n2` 
 * `XOR(n1, n2)` ==> result of `n1 ^ n2` 

>⚠️ **Warning:** arguments and returning type of arithmetic functions declaration listed above (`ADD`, `ADD_0xNN`, etc) must be the same, otherwise you will got INTERR 50830 or 50831 

### Opaque Predicates removers mostly derived from HexRaysDeob plugin by Rolf Rolles and Takahiro Haruyama

Below `x` and `y` are expressions. `a`, `b`, `c`, `d` - numbers
 * `(x & 1) | (y & 1)`    ==> `(x | y) & 1`
 * `(x & 1) ^ (y & 1)`    ==> `(x ^ y) & 1`
 * `(x-a)+b` or `(x+a)+b` ==> `x+(b-a)` or `x+(b+a)`
 * `(x-a)-b` or `(x+a)-b` ==> `x-(b+a)` or `x-(b-a)`
 * `(x * (x-1)) & 1`      ==> `0`
 * `~(x * (x - 1)) | -2`  ==> `-1`
 * `(x & y) | (x ^ y)`    ==> `x | y`
 * `x | !x`               ==> `1`
 * `(x & c) | ( ~x & d)`  ==> `x ^ d` (where c and d are numbers such that c == ~d)
 * `!(!x || !y)`          ==> `x && y`
 * `~(~x | n)`            ==> `x & ~n`
 * `x ^ a == b`           ==> `x == a ^ b`

