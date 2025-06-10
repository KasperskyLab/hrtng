## Refactoring (global Find and Replace)
Context menu *"Refactoring... (Shift-R)"*

Right click and select *"Refactoring..."* on any highlighted word in Disassembly, Decompiler, Types or Structures view.
Non-modal dialog with results of searching the highlighted word is appeared.

The results are grouped to following folders:
 * **func** - the word is part of function name;
 * **farg** - ... part of an argument name in the function prototype (whole function prototype is displayed);
 * **gvar** - ... part of a global variable name;
 * **lvar** - ... part of a local variable name (all matched variables are displayed in one line, then symbol `@` and the function name is appended to the line);
 * **cmts** - ... part of a user defined comment (too long comment is displayed incomplete)
 * **nfmt** - ... part of a typename of user defined number format (structure for `offsetof`/`sizeof` or enum name)
 * **type** - ... part of a type name (only structures and unions for IDA versions less 8.5);
 * **udm**  - ... part of a struct or union member's name (the full name of the member is displayed);
 * **msig** - ... part of [microcode signature](msig.md) name;
 * **note** - ... part of IDA notepad text

In the results list:
 * Double click or press "Enter" to see the function/type body.
 * Press "Del" to skip Replace operation for the currently selected row. The ignored line be shown as a ~~strikeout~~. Press "Del" again to undo skipping.
 * Right click and uncheck *"Show folders"* for a plain view. Plain view is the only option for IDA versions less 7.7.
 * Right click and select *"Columns..."* to see two more columns (*"Address/TypeID"* and *"Kind"*) are hidden by default.

You may alter *"Search for"* and *"Replace with"* fields. Spaces on the both ends of Search and Replace strings are removed. The results list will be dynamically updated.

>📝 **Note:** "Whole words only" mode suddenly means underline symbol ('_') as the word divider. The only ISO basic Latin alphabet letters and numbers belong to word characters set.

Press *"OK"* button to apply changes. Check "Output window" to see if something went wrong.  
All renaming (except MSIGs) may be undone with "Ctrl-Z" hotkey since IDA 7.7
