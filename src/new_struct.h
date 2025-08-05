//Evolution of new_struct.h from https://github.com/nihilus/hexrays_tools

#pragma once
#include <pro.h>
#include <map>
#include <set>
#include <typeinf.hpp>
#include <hexrays.hpp>

struct ida_local typerecord_t
{
	tinfo_t type;
	bool enabled;

	typerecord_t():type(), enabled(true){}

	DECLARE_COMPARISONS(typerecord_t)	
	{	
		return type.compare(r.type);
	};
};

// vector of types
struct ida_local typevec_t:qvector<typerecord_t>
{
	unsigned int disabled_count;
	typevec_t() : disabled_count(0) {}
	bool get_first_enabled(tinfo_t & type)
	{		
		for(iterator i=begin(); i!=end(); i++) {
			if(i->enabled) {
				type = i->type;
				return true;
			}
		}
		return false;
	}
	bool in_conflict() const
	{
		return size() > 1 + disabled_count;
	}
	void clear()
	{
		qvector<typerecord_t>::clear();
		disabled_count = 0;		
	}
};

struct ida_local scan_info_t
{	
	typevec_t types;
	uint32 nesting_counter;
	bool is_array;
	scan_info_t() : types(), nesting_counter(0), is_array(false) {}
};

struct ida_local argument_t
{
	uval_t arg_num;
	uval_t arg_cnt;
};

typedef std::map<ea_t, uval_t> function_adjustments_t;
typedef std::map<ea_t, argument_t> arguments_t;
typedef std::map<uval_t, uval_t> max_adjustments_t;
typedef std::set<ea_t> visited_functions_t;
typedef qvector<ea_t> global_pointers_t;
typedef std::pair<uval_t,lvar_locator_t> scanned_variable_t; // offset_for_var_idx: var
typedef std::map<ea_t,  qvector<scanned_variable_t> > scanned_variables_t; //func_ea is index
typedef std::map<uval_t,  tinfo_t> types_cache_t;

//mapping offset -> set of possible types
struct ida_local field_info_t: std::map<uval_t, scan_info_t>
{
	uval_t current_offset;                       // master offset (for nested structs)
	max_adjustments_t max_adjustments;           // track maximum accessed offset (for every var master offset)
	function_adjustments_t function_adjustments; // map func_ea <-> offset used in call
	visited_functions_t visited_functions;       // used to 'show pseudocode of next function'
	arguments_t argument_numbers;                // map func_ea <-> argument num in call
	global_pointers_t global_pointers;           // scan global var
	scanned_variables_t scanned_variables;       // scan local var
	types_cache_t types_cache;                   // types of substructs

	field_info_t() : current_offset(0) { }

	void update_max_offset(uval_t current, uval_t max);
	uval_t types_at_idx_qty(uval_t idx) const;
	bool flip_enabled_status(uval_t idx, uval_t position);
	bool to_type(tinfo_t & out_type, field_info_t::iterator * bgn = NULL, field_info_t::iterator * end = NULL);
	void clear();	
};

extern field_info_t fi;
bool can_be_converted_to_ptr(vdui_t &vu, bool bVarTesting);

