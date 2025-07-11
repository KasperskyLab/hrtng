## Jump to indirect call destination
Context menu *"Jump to indirect call (J)"*

Double click, press "j" or right click on indirect call and select *"Jump to indirect call (J)"* to navigate pseudocode view to call target.

#### How does it work, and why doesn't.
There is no any magic behind this feature: no symbolic nor debugging/emulation execution. 

Descry three main types of indirect calls: 
1) Indirect calls generated by the optimising compiler. When inside one proc are a few calls to another the compiler may put to register the pointer to callee and generate code that uses this register for indirect calls
```
mov     esi, ds:RtlInitUnicodeString
call    esi ; RtlInitUnicodeString
...
call    esi ; RtlInitUnicodeString
...
call    esi ; RtlInitUnicodeString
```
Usually hex-rays decompiler perfectly converts such indirect calls to direct. If not, the decompiler might decided `esi` in the example above has been spoiled somewhere between calls and created local variable for underlying calls. To fix it need to resolve register collision or dial with it like with Callback case described below.

2) C++ virtual method call. Pointers to virtual functions grouped into the table known as VTBL usually stored in read only data segment. Pointer to VTBL is stored in the first member of C++ class instance. The plugin [automatically detects or assist in manual creation of virtual table](virtual-calls.md).
   * To dial with virtual calls properly, you should first visit C++ class constructor/destructor where create IDA structures for class type and VTBL. The plugin establish link between VTBL and class structure. And then carefully propagate class type from the definition to usage. Notes about effective propagation below in Callback section. We may consider VTBL as a special case of structure stores callback pointers.

3) Callback - pointer to a function stored as data somewhere: local/global variable or struct member. The main hint for the plugin here is the callee name. "Jump to indirect call (J)" is just a bit smarter replacement of invoking menu "Edit" -> "Jump to address (G)" with CalleeName.  So to work it properly the following conditions must be met:
   * The plugin must see value (pointer to the callback function) assignment to the variable or struct member before the variable is used for call.
   * Auto-renamer feature should be turned on to help you propagate callee name and type across call graph
   * For the already seen code combination of [Recursively decompile](recur-decomp.md) + [Microcode signatures](msig.md) + [Import-function-prototype](import_unf_types.md) features may be helpful to quick name and type propagation between definition and usage of the function pointer
   * Again, the name of callee must exist in the IDA's functions list. If one of variable or target function was renamed without renaming the counterpart - the feature is broken. 
   * Good news here - if the function pointer is stored inside struct member and “Jump to indirect call (J)” has been successfully executed at least once - the plugin establish cross reference link between struct member and destination proc and [automatically synchronise following renaming](rename-recast.md) similar to VTBL method.
