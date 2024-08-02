## Fix stack pointer for indirect call
Context menu *"Force call type"* or *"Set call type"*

Sometimes IDA wrongly calculates stack pointer delta on indirect call. For example:
```
10004D9E 020 40                    inc     eax
10004D9F 020 50                    push    eax
10004DA0 024 6A 08                 push    8
10004DA2 028 FF 96 E4 00 00 00     call    dword ptr [esi+0E4h]
10004DA8 020 50                    push    eax
10004DA9 024 FF 96 E8 00 00 00     call    dword ptr [esi+0E8h]
10004DAF 020 8B D8                 mov     ebx, eax
```
Decompiled as:
```
    v3 = ((int (__stdcall *)(int, size_t))::api->GetProcessHeap)(8, v5);
    v4 = (const void *)((int (__stdcall *)(int))api->HeapAlloc)(v3);
```
For the call at 0x10004DA2 IDA assumes two arguments, and for the call at 0x10004DA9 - one argument. That's wrong. Context menu items *"Force call type"* or *"Set call type"* may fix pseudocode representation for these statements but leaves stack unbalanced, and further decompilation may goes wrong or even cause decompiler internal errors.

The plugin checks and fix mismatching dissasembler's stack pointer delta for such a call and calling convention's purged stack size on *"Force call type"* or *"Set call type"*.
