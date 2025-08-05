//Evolution of structures.h from https://github.com/nihilus/hexrays_tools
#pragma once

tid_t create_VT_struc(ea_t VT_ea, const char* basename, uval_t idx = BADADDR, unsigned int* vt_len = NULL, bool autoScan = false);
int create_VT(tid_t parent, ea_t VT_ea, bool autoScan = false);
void auto_create_vtbls(cfunc_t *cfunc);

typedef qvector<tid_t> tidvec_t;
asize_t struct_get_member(tid_t strId, asize_t offset, tid_t* last_member, tidvec_t* trace = NULL, asize_t adjust = 0);

bool confirm_create_struct(tinfo_t &out_type, qstring& out_type_name, tinfo_t &in_type, const char* sprefix);

bool struct_has_member(tid_t strId, asize_t offset);
bool print_struct_member_name(tid_t strcId, asize_t offset, qstring* name, bool InRecur = false);
bool print_struct_member_type(tid_t membId, qstring *tname);
tinfo_t type_by_tid(tid_t tid);

struct ida_local matched_structs_t : public chooser_t
{
	static const int widths[];
	static const char* const header[];
	tidvec_t list;

	matched_structs_t() : chooser_t(CH_KEEP | CH_MODAL, 1, widths, header, "[hrt] Matched structs") {}
	virtual size_t idaapi get_count() const { return list.size(); }
	virtual void idaapi get_row(qstrvec_t* cols, int* icon_, chooser_item_attrs_t* attrs, size_t n) const;
};

#if IDA_SDK_VERSION < 850
void structs_reg_act();
void structs_unreg_act();
void add_structures_popup_items(TWidget *view, TPopupMenu *p);

ea_t get_memb2proc_ref(struc_t* s, member_t* m);
#else
ea_t get_memb2proc_ref(tinfo_t& struc, uint32 membOffInBytes);
#endif // IDA_SDK_VERSION < 850
bool add_proc2memb_ref(ea_t proc, tid_t memb);
void get_proc2memb_refs(ea_t proc, tidvec_t* membs);
void get_memb2proc_refs(tid_t memb, eavec_t* eav);
