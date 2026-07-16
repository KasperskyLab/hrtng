#pragma once
#if IDA_SDK_VERSION < 940

#define INV_IF_ACTION_NAME "ht:invertif"

void init_invert_if();
cinsn_t *find_if_statement(vdui_t *vu);
void convert_marked_ifs(cfunc_t *cfunc);

#endif //IDA_SDK_VERSION < 940
