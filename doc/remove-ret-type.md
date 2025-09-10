## Removes function's return type converting it to void func(...)
Context menu *"Remove return type"*  
> ⚠️ Obsolete since IDA 7.5 has the [same](https://hex-rays.com/products/decompiler/manual/cmd_adddel_rettype.shtml). Available when build with an older SDK

Sometimes function does not return any value but Hex-Rays thinks it does. It was very tiresome to type "home, y, home, ctrl-shift-left, "void", enter" so here is a way to do it on one click.

Just right click on first line of pseudocode and choose *"Remove return type"*.
