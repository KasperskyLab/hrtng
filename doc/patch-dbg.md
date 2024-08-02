## Patch from debugger / Patch from file
Menu *"Edit/Patch program/Patch from debugger"* and *"Edit/Patch program/Patch from file"*

For self-modifying, self-unpacked and self-decrypting binaries you can go over self-modification code with debugger. Then staying on breakpoint select area of modified code/data and click menu entry *"Edit/Patch program/Patch from debugger"*. You may repeat these steps few times. When debugger session be stopped the plugin patches these areas of data/code by values were while debugging. You can continue to analyze binary in static way.

>📝 **Note:** Only memory is mapped by loaded binary can be patched by this trick: not heap, not stack. Such memory areas may be exported into dedicated file from IDA with menu *"Edit/Export data (Shift-E)"* during debugging.

![Patch from debugger](patch-dbg.gif)

You may also apply a big patch from binary file instead of copy-paste hex values to IDA's dialog *"Edit/Patch program/Change byte..."*  by using *"Edit/Patch program/Patch from file"*. For example: file created by *"Edit/Export data (Shift-E)"* may be applied as patch into appropriate space or new database segment.
