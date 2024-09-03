//Evolution of structures.h from https://github.com/nihilus/hexrays_tools
#pragma once

tid_t create_VT_struc(ea_t VT_ea, const char* basename, uval_t idx = BADADDR, unsigned int* vt_len = NULL);
int create_VT(tid_t parent, ea_t VT_ea);

typedef qvector<tid_t> tidvec_t;
asize_t struct_get_member(tid_t strId, asize_t offset, tid_t* last_member, tidvec_t* trace = NULL, asize_t adjust = 0);

