## Smart rename func
Context menu *"Rename func... (Ctrl-N)"*

Just right click to any place of pseudocode and choose *"Rename func..."*. or press "Ctrl-N" for renaming the function a bit smarter way.  
The plugin proposes a new name for the function:
 * currently highlighted word in the function body (ex: `doSomething`)
 * old name of the function if it is user-defined

Before the main part of the new name may be inserted a class name, if the first or currently selected function argument has type of pointer to named struct. (ex: `cMyClass::doSomething`)

Additionally possible names conflict is resolved with using suffixes without underline (`'_'`) symbol to not confuse name-to-type conversion for the case when function is used for FLIRT or MSIG signatures building.
