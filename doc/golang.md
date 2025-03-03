## Set calling conventions a bit closer to Go-lang
Context menu *"Convert to __usercall golang (Shift-G)"*
> ⚠️ Probably obsolete since IDA 7.6 properly support  golang binaries analysis. But may be helpful in cases when IDA doesnt recognize golang binaries.  
> ⚠️ This feature is turned off since IDA 9.0/8.5

This feature has been added for anayizing binaries produced by [Go compiler](https://golang.org). Press "Shift-G" on the first line of pseudocode and:
- Calling convention of the function will be changed to `__usercall`
- All registers will be marked as spoiled
- Return type will be set to "`void`"
- The function arguments will be destroyed and recreated from the stack frame
- Stack arguments area will be marked as deprecated for "global dead elimination" decompiler step
- Local variables that share the same stack location will be mapped together

>📝 **Note:** 
> - Even after all these steps Golang decompiled pseudocode is in a mess because of hard stack locations re-usage.
> - Do not forget to switch compiler (menu *Options/Compiler*) to "GNU C++"
