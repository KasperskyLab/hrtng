## Smart rename func
Context menu *"Rename func... (Ctrl-N)"*

Just right click on first line of pseudocode and choose *"Rename func..."*. or press "Ctrl-N" for renaming the function a bit smarter way.  
Old name of the function, if exist, for example `doSomething` and the type name of the current/first argument of function will be connected together and proposed as new name like `cMyClass::doSomething`.  
Additionally possible names conflict is resolved with using suffixes without underline (`'_'`) symbol to not confuse name-to-type conversion for the case when function is used for FLIRT or MSIG signatures building.
