#pragma once
void opt_init();
void opt_done();

bool InsertOp(mblock_t* mb, mlist_t& ml, mop_t* op);
minsn_t* my_find_def_backwards(mblock_t* mb, mlist_t& ml, minsn_t* start);

