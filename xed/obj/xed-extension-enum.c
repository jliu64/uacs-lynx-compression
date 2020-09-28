/// @file xed-extension-enum.c

// This file was automatically generated.
// Do not edit this file.

#include <string.h>
#include <assert.h>
#include "xed-extension-enum.h"

typedef struct {
    const char* name;
    xed_extension_enum_t value;
} name_table_xed_extension_enum_t;
static const name_table_xed_extension_enum_t name_array_xed_extension_enum_t[] = {
{"INVALID", XED_EXTENSION_INVALID},
{"3DNOW", XED_EXTENSION_3DNOW},
{"ADOX_ADCX", XED_EXTENSION_ADOX_ADCX},
{"AES", XED_EXTENSION_AES},
{"AVX", XED_EXTENSION_AVX},
{"AVX2", XED_EXTENSION_AVX2},
{"AVX2GATHER", XED_EXTENSION_AVX2GATHER},
{"AVX512EVEX", XED_EXTENSION_AVX512EVEX},
{"AVX512VEX", XED_EXTENSION_AVX512VEX},
{"AVXAES", XED_EXTENSION_AVXAES},
{"BASE", XED_EXTENSION_BASE},
{"BMI1", XED_EXTENSION_BMI1},
{"BMI2", XED_EXTENSION_BMI2},
{"CET", XED_EXTENSION_CET},
{"CLDEMOTE", XED_EXTENSION_CLDEMOTE},
{"CLFLUSHOPT", XED_EXTENSION_CLFLUSHOPT},
{"CLFSH", XED_EXTENSION_CLFSH},
{"CLWB", XED_EXTENSION_CLWB},
{"CLZERO", XED_EXTENSION_CLZERO},
{"ENQCMD", XED_EXTENSION_ENQCMD},
{"F16C", XED_EXTENSION_F16C},
{"FMA", XED_EXTENSION_FMA},
{"FMA4", XED_EXTENSION_FMA4},
{"GFNI", XED_EXTENSION_GFNI},
{"INVPCID", XED_EXTENSION_INVPCID},
{"LONGMODE", XED_EXTENSION_LONGMODE},
{"LZCNT", XED_EXTENSION_LZCNT},
{"MCOMMIT", XED_EXTENSION_MCOMMIT},
{"MMX", XED_EXTENSION_MMX},
{"MONITOR", XED_EXTENSION_MONITOR},
{"MONITORX", XED_EXTENSION_MONITORX},
{"MOVBE", XED_EXTENSION_MOVBE},
{"MOVDIR", XED_EXTENSION_MOVDIR},
{"MPX", XED_EXTENSION_MPX},
{"PAUSE", XED_EXTENSION_PAUSE},
{"PCLMULQDQ", XED_EXTENSION_PCLMULQDQ},
{"PCONFIG", XED_EXTENSION_PCONFIG},
{"PKU", XED_EXTENSION_PKU},
{"PREFETCHWT1", XED_EXTENSION_PREFETCHWT1},
{"PT", XED_EXTENSION_PT},
{"RDPID", XED_EXTENSION_RDPID},
{"RDPRU", XED_EXTENSION_RDPRU},
{"RDRAND", XED_EXTENSION_RDRAND},
{"RDSEED", XED_EXTENSION_RDSEED},
{"RDTSCP", XED_EXTENSION_RDTSCP},
{"RDWRFSGS", XED_EXTENSION_RDWRFSGS},
{"RTM", XED_EXTENSION_RTM},
{"SERIALIZE", XED_EXTENSION_SERIALIZE},
{"SGX", XED_EXTENSION_SGX},
{"SGX_ENCLV", XED_EXTENSION_SGX_ENCLV},
{"SHA", XED_EXTENSION_SHA},
{"SMAP", XED_EXTENSION_SMAP},
{"SMX", XED_EXTENSION_SMX},
{"SNP", XED_EXTENSION_SNP},
{"SSE", XED_EXTENSION_SSE},
{"SSE2", XED_EXTENSION_SSE2},
{"SSE3", XED_EXTENSION_SSE3},
{"SSE4", XED_EXTENSION_SSE4},
{"SSE4A", XED_EXTENSION_SSE4A},
{"SSSE3", XED_EXTENSION_SSSE3},
{"SVM", XED_EXTENSION_SVM},
{"TBM", XED_EXTENSION_TBM},
{"TSX_LDTRK", XED_EXTENSION_TSX_LDTRK},
{"VAES", XED_EXTENSION_VAES},
{"VIA_PADLOCK_AES", XED_EXTENSION_VIA_PADLOCK_AES},
{"VIA_PADLOCK_MONTMUL", XED_EXTENSION_VIA_PADLOCK_MONTMUL},
{"VIA_PADLOCK_RNG", XED_EXTENSION_VIA_PADLOCK_RNG},
{"VIA_PADLOCK_SHA", XED_EXTENSION_VIA_PADLOCK_SHA},
{"VMFUNC", XED_EXTENSION_VMFUNC},
{"VPCLMULQDQ", XED_EXTENSION_VPCLMULQDQ},
{"VTX", XED_EXTENSION_VTX},
{"WAITPKG", XED_EXTENSION_WAITPKG},
{"WBNOINVD", XED_EXTENSION_WBNOINVD},
{"X87", XED_EXTENSION_X87},
{"XOP", XED_EXTENSION_XOP},
{"XSAVE", XED_EXTENSION_XSAVE},
{"XSAVEC", XED_EXTENSION_XSAVEC},
{"XSAVEOPT", XED_EXTENSION_XSAVEOPT},
{"XSAVES", XED_EXTENSION_XSAVES},
{"LAST", XED_EXTENSION_LAST},
{0, XED_EXTENSION_LAST},
};

        
xed_extension_enum_t str2xed_extension_enum_t(const char* s)
{
   const name_table_xed_extension_enum_t* p = name_array_xed_extension_enum_t;
   while( p->name ) {
     if (strcmp(p->name,s) == 0) {
      return p->value;
     }
     p++;
   }
        

   return XED_EXTENSION_INVALID;
}


const char* xed_extension_enum_t2str(const xed_extension_enum_t p)
{
   xed_extension_enum_t type_idx = p;
   if ( p > XED_EXTENSION_LAST) type_idx = XED_EXTENSION_LAST;
   return name_array_xed_extension_enum_t[type_idx].name;
}

xed_extension_enum_t xed_extension_enum_t_last(void) {
    return XED_EXTENSION_LAST;
}
       
/*

Here is a skeleton switch statement embedded in a comment


  switch(p) {
  case XED_EXTENSION_INVALID:
  case XED_EXTENSION_3DNOW:
  case XED_EXTENSION_ADOX_ADCX:
  case XED_EXTENSION_AES:
  case XED_EXTENSION_AVX:
  case XED_EXTENSION_AVX2:
  case XED_EXTENSION_AVX2GATHER:
  case XED_EXTENSION_AVX512EVEX:
  case XED_EXTENSION_AVX512VEX:
  case XED_EXTENSION_AVXAES:
  case XED_EXTENSION_BASE:
  case XED_EXTENSION_BMI1:
  case XED_EXTENSION_BMI2:
  case XED_EXTENSION_CET:
  case XED_EXTENSION_CLDEMOTE:
  case XED_EXTENSION_CLFLUSHOPT:
  case XED_EXTENSION_CLFSH:
  case XED_EXTENSION_CLWB:
  case XED_EXTENSION_CLZERO:
  case XED_EXTENSION_ENQCMD:
  case XED_EXTENSION_F16C:
  case XED_EXTENSION_FMA:
  case XED_EXTENSION_FMA4:
  case XED_EXTENSION_GFNI:
  case XED_EXTENSION_INVPCID:
  case XED_EXTENSION_LONGMODE:
  case XED_EXTENSION_LZCNT:
  case XED_EXTENSION_MCOMMIT:
  case XED_EXTENSION_MMX:
  case XED_EXTENSION_MONITOR:
  case XED_EXTENSION_MONITORX:
  case XED_EXTENSION_MOVBE:
  case XED_EXTENSION_MOVDIR:
  case XED_EXTENSION_MPX:
  case XED_EXTENSION_PAUSE:
  case XED_EXTENSION_PCLMULQDQ:
  case XED_EXTENSION_PCONFIG:
  case XED_EXTENSION_PKU:
  case XED_EXTENSION_PREFETCHWT1:
  case XED_EXTENSION_PT:
  case XED_EXTENSION_RDPID:
  case XED_EXTENSION_RDPRU:
  case XED_EXTENSION_RDRAND:
  case XED_EXTENSION_RDSEED:
  case XED_EXTENSION_RDTSCP:
  case XED_EXTENSION_RDWRFSGS:
  case XED_EXTENSION_RTM:
  case XED_EXTENSION_SERIALIZE:
  case XED_EXTENSION_SGX:
  case XED_EXTENSION_SGX_ENCLV:
  case XED_EXTENSION_SHA:
  case XED_EXTENSION_SMAP:
  case XED_EXTENSION_SMX:
  case XED_EXTENSION_SNP:
  case XED_EXTENSION_SSE:
  case XED_EXTENSION_SSE2:
  case XED_EXTENSION_SSE3:
  case XED_EXTENSION_SSE4:
  case XED_EXTENSION_SSE4A:
  case XED_EXTENSION_SSSE3:
  case XED_EXTENSION_SVM:
  case XED_EXTENSION_TBM:
  case XED_EXTENSION_TSX_LDTRK:
  case XED_EXTENSION_VAES:
  case XED_EXTENSION_VIA_PADLOCK_AES:
  case XED_EXTENSION_VIA_PADLOCK_MONTMUL:
  case XED_EXTENSION_VIA_PADLOCK_RNG:
  case XED_EXTENSION_VIA_PADLOCK_SHA:
  case XED_EXTENSION_VMFUNC:
  case XED_EXTENSION_VPCLMULQDQ:
  case XED_EXTENSION_VTX:
  case XED_EXTENSION_WAITPKG:
  case XED_EXTENSION_WBNOINVD:
  case XED_EXTENSION_X87:
  case XED_EXTENSION_XOP:
  case XED_EXTENSION_XSAVE:
  case XED_EXTENSION_XSAVEC:
  case XED_EXTENSION_XSAVEOPT:
  case XED_EXTENSION_XSAVES:
  case XED_EXTENSION_LAST:
  default:
     xed_assert(0);
  }
*/