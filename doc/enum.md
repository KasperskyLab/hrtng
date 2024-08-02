## Automatic enum substitution (needs "literal.txt" file inside the IDA plugins folder)
IDA doesn't known where enum type might be used. The plugin associates some of proc and struct names with used enum types and automatically converts numeric values into enum representation.
```
// call without plugin
hFile = CreateFileW(&FileName, 0x80000000, 7u, 0, 3u, 0x80u, 0);

// became with plugin to:
hFile = CreateFileW(&FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
```
>📝 **Note:** When IDA typelibrary (til file) for corresponding enum is not loaded, the plugin instead constant replacement makes comment with numbers decoding.

Format of literal database is simple, each declaration consist four parts:
```
1) <FunctionName> or <STRUCT><space><StructName> in line begginning (no spaces or tabs before)
2) <space> <FuncArgumentNumber> or <StructFieldName> <space> <Type> : Where FuncArgumentNumber started from 1. 0 means return value. Type is "enum" for exclusive values or "bits" for values may be combined with bitwise OR
3) <space> <space> <LiteralName> <space> <Value>
4) empty line
```

Example of `IDADIR/plugins/literal.txt`:
```
CreateFile
 2 bits
  FILE_ALL_ACCESS 0x1f01ff
  GENERIC_ALL 0x10000000
  GENERIC_EXECUTE 0x20000000
  GENERIC_WRITE 0x40000000
  GENERIC_READ 0x80000000
 3 bits
  FILE_SHARE_READ 0x1
  FILE_SHARE_WRITE 0x2
  FILE_SHARE_DELETE 0x4
 5 enum
  CREATE_NEW 0x1
  CREATE_ALWAYS 0x2
  OPEN_EXISTING 0x3
  OPEN_ALWAYS 0x4
  TRUNCATE_EXISTING 0x5
6 bits
  FILE_ATTRIBUTE_READONLY 0x1
  FILE_ATTRIBUTE_HIDDEN 0x2
  FILE_ATTRIBUTE_SYSTEM 0x4
  FILE_ATTRIBUTE_NORMAL 0x80

STRUCT addrinfo
 ai_family enum
  AF_INET 0x2
  AF_INET6 0x17
 ai_socktype enum
  SOCK_STREAM 0x1
  SOCK_DGRAM 0x2
  SOCK_RAW 0x3
 ai_protocol enum
  IPPROTO_IP 0x0
  IPPROTO_ICMP 0x1
  IPPROTO_TCP 0x6
 IPPROTO_UDP 0x11

```
