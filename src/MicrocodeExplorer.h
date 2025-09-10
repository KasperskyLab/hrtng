#pragma once

#if IDA_SDK_VERSION < 920
void registerMicrocodeExplorer();
void unregisterMicrocodeExplorer();
void ShowMicrocodeExplorer(mbl_array_t* mba, const char* name);
#endif //IDA_SDK_VERSION < 920

