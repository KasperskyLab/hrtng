## Collapse selection
Context menu *"Collapse selection"* and *"Remove collapsible 'if(42) ...' blocks"*

Sometimes decompiler's output is overloaded with non-significant lines. The idea is to hide these lines by IDA collapse feature to make understanding of function meaning a bit easier.

Select single-entry/single-exit block of code where the block entry and exit belong to the same outer block and pick *"Collapse selection"* from the context menu. This code will be enclosed into fake "`if (42) { <code> }`" statement and collapsed.  
All "`if (42)`" statements in the function may be cleared with context menu *"Remove collapsible 'if(42) ...' blocks"*

![Collapse selection](collapse.gif)
