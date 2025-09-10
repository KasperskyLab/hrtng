#pragma once

#define INV_IF_ACTION_NAME "ht:invertif"

void init_invert_if();
cinsn_t *find_if_statement(vdui_t *vu);
void convert_marked_ifs(cfunc_t *cfunc);
