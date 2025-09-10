## Remove function's argument
Context menu *"Remove this argument (A)"*  
> ⚠️ Obsolete since IDA 7.5 has the [same](https://hex-rays.com/products/decompiler/manual/cmd_delarg.shtml). Available when build with an older SDK

Sometimes Hex-Rays thinks that a register is used as an argument for a function but it isn't so. It was also tiresome to type "home, home, y, ctrl->right, ctrl-shift-right, delete, enter". So here is an easiest way to deal with it.

Just select that argument in the first line of pseudocode and choose *"Remove this argument"*.
