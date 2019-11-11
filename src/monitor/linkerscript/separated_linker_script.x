PHDRS
{
  headers PT_PHDR PHDRS ;
  header_load PT_LOAD FILEHDR PHDRS ;
  interp PT_INTERP ;
  inter_load PT_LOAD;
  text PT_LOAD ;
  rosegment PT_LOAD ;
  data PT_LOAD ;
  dynamic PT_DYNAMIC ;
}

SECTIONS
{
  . = SIZEOF_HEADERS;
  . = . + 0x1000;
  .interp : { *(.interp) } :interp :inter_load
  . = . + 0x1000;
  .text : { *(.text) } :text
  . = . + 0x1000;
  .rodata : { *(.rodata) }:rosegment /* defaults to :text */
  . = . + 0x1000;
  .data : { *(.data) } :data
  . = . + 0x1000;
  .dynamic : { *(.dynamic) } :data :dynamic
}
