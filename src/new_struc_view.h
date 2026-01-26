//Evolution of new_struc_view.h from https://github.com/nihilus/hexrays_tools

#pragma once
bool show_new_struc_view();
bool close_new_struc_view();
void new_struct_view_reg_act();
void new_struct_view_unreg_act();

struct ida_local function_list_t : public chooser_t
{
	eavec_t functions;
	static const int widths[];
	static const char* const header[];

	function_list_t(const char* title) : chooser_t(CH_KEEP | CH_MODAL, 2, widths, header, title) {}
	virtual size_t idaapi get_count() const { return functions.size(); }
	virtual void idaapi get_row(qstrvec_t* cols, int* icon_, chooser_item_attrs_t* attrs, size_t n) const
	{
		qstrvec_t& cols_ = *cols;
		ea_t ea = functions[n];
		cols_[0].sprnt("%a", ea);
		cols_[1] = get_short_name(ea);

		func_t* f = get_func(ea);
		if (f)
			get_func_cmt(&cols_[2], f, true);
	}
};

