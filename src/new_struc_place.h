//Evolution of new_struc_place.h from https://github.com/nihilus/hexrays_tools

#pragma once

#include <pro.h>
#include <ida.hpp>
#include <kernwin.hpp>

define_place_exported_functions(new_struc_place_t)
class ida_local new_struc_place_t : public place_t
{
public:
	uval_t idx;
	uval_t subtype;
	
	new_struc_place_t(void) : place_t(0), idx(0), subtype(0) { }
	new_struc_place_t(uval_t idx_) : place_t(0), idx(idx_), subtype(0) {}
	new_struc_place_t(uval_t idx_, uval_t st) : place_t(0), idx(idx_), subtype(st) {}
	define_place_virtual_functions(new_struc_place_t);
};

void register_new_struc_place();

