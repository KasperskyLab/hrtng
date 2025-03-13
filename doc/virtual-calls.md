## Virtual calls assists
Context menu *"Add VT"*, *"Add VT struct"*

- *"Add VT"* in Pseudocode view: Right click on VTBL assignment statement (usually in constructor and destructor proc) and select *"Add VT"*. VTBL structure be created and tied to vtbl member.  
If vtbl member is already defined:
  * On the same VTBL assingment: the plugin creates a new VTBL structure. It may be useful if previous VTBL structure was incomplete.
  * On the another VTBL: the plugin creates a union type with VTBL structures of the base and derived classes.

![Add VT](cr_struc-add_vt.gif)

- *"Add VT struct"* in IDA View: Right click on beginning of virtual table and select *"Add VT struct"*. VTBL structure be created and Structures view with the structure be opened. You need to manually tie the VTBL struct to an appropriate class's structure member.
 
![Add VT](add-vt-struc.gif)
