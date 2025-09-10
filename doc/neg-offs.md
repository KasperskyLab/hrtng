## Deals with structures with negative offsets or access based on offsets in a middle of structure
Context menu *"Use CONTAINER_OF here"*, *"Destroy CONTAINER_OF"*  
> ⚠️ Obsolete since IDA 7.4 has better alternative - [shifted pointers](https://hex-rays.com/products/ida/support/idadoc/1695.shtml). Available when build with an older SDK

Sometimes compilers produces code where the pointer to a middle of struct is taken as base pointer, and then access to structure members are followed as positive and negative offsets from the base pointer.  
For example in the following code that copies sections on PE image to new base. `p_VSize` is a base pointer in a middle of `IMAGE_SECTION_HEADER` structure.
```
    p_VSize = (__int64)&pe->OptionalHeader.SizeOfInitializedData + pe->FileHeader.SizeOfOptionalHeader;
    do
    {
      Size = *(_DWORD *)(p_VSize + 8);
      if ( *(_DWORD *)p_VSize < Size )
        Size = *(_DWORD *)p_VSize;
      memmove((void *)(newImgBase + *(unsigned int *)(p_VSize + 4)), &oldImgBase[*(unsigned int *)(p_VSize + 12)], Size);
      ++i;
      p_VSize += sizeof(IMAGE_SECTION_HEADER);
    }
    while ( pe->FileHeader.NumberOfSections > i );
```
You can right click to somewhere inside `p_VSize + 8` expression and select *"Use CONTAINER_OF here"*, enter base pointer struct member name in form `IMAGE_SECTION_HEADER.Misc` or as `IMAGE_SECTION_HEADER + 8` And the code be converted to following form:
```
    p_VSize = (__int64)&pe->OptionalHeader.SizeOfInitializedData + pe->FileHeader.SizeOfOptionalHeader;
    do
    {
      Size = CONTAINER_OF(IMAGE_SECTION_HEADER.Misc)->SizeOfRawData;
      if ( *(_DWORD *)p_VSize < Size )
        Size = *(_DWORD *)p_VSize;
      memmove((void *)(newImgBase + CONTAINER_OF(IMAGE_SECTION_HEADER.Misc)->VirtualAddress), &oldImgBase[CONTAINER_OF(IMAGE_SECTION_HEADER.Misc)->PointerToRawData], Size);
      ++i;
      p_VSize += sizeof(IMAGE_SECTION_HEADER);
    }
    while ( pe->FileHeader.NumberOfSections > i);
```
In some conditions the plugin able to detect base pointer assignment and insert `CONTAINER_OF` automatically.  
Such automatic `CONTAINER_OF` sometimes may be less informative then original code. So you can right click to `CONTAINER_OF` and select *"Destroy CONTAINER_OF"*  
This feature looks like similar to Milan's `NEGATIVE_STRUCT_CAST` and IDA's `CONTAINING_RECORD` but based on another idea.
