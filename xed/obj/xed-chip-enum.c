/// @file xed-chip-enum.c

// This file was automatically generated.
// Do not edit this file.

#include <string.h>
#include <assert.h>
#include "xed-chip-enum.h"

typedef struct {
    const char* name;
    xed_chip_enum_t value;
} name_table_xed_chip_enum_t;
static const name_table_xed_chip_enum_t name_array_xed_chip_enum_t[] = {
{"INVALID", XED_CHIP_INVALID},
{"I86", XED_CHIP_I86},
{"I86FP", XED_CHIP_I86FP},
{"I186", XED_CHIP_I186},
{"I186FP", XED_CHIP_I186FP},
{"I286REAL", XED_CHIP_I286REAL},
{"I286", XED_CHIP_I286},
{"I2186FP", XED_CHIP_I2186FP},
{"I386REAL", XED_CHIP_I386REAL},
{"I386", XED_CHIP_I386},
{"I386FP", XED_CHIP_I386FP},
{"I486REAL", XED_CHIP_I486REAL},
{"I486", XED_CHIP_I486},
{"PENTIUMREAL", XED_CHIP_PENTIUMREAL},
{"PENTIUM", XED_CHIP_PENTIUM},
{"QUARK", XED_CHIP_QUARK},
{"PENTIUMMMXREAL", XED_CHIP_PENTIUMMMXREAL},
{"PENTIUMMMX", XED_CHIP_PENTIUMMMX},
{"ALLREAL", XED_CHIP_ALLREAL},
{"PENTIUMPRO", XED_CHIP_PENTIUMPRO},
{"PENTIUM2", XED_CHIP_PENTIUM2},
{"PENTIUM3", XED_CHIP_PENTIUM3},
{"PENTIUM4", XED_CHIP_PENTIUM4},
{"P4PRESCOTT", XED_CHIP_P4PRESCOTT},
{"P4PRESCOTT_NOLAHF", XED_CHIP_P4PRESCOTT_NOLAHF},
{"P4PRESCOTT_VTX", XED_CHIP_P4PRESCOTT_VTX},
{"CORE2", XED_CHIP_CORE2},
{"PENRYN", XED_CHIP_PENRYN},
{"PENRYN_E", XED_CHIP_PENRYN_E},
{"NEHALEM", XED_CHIP_NEHALEM},
{"WESTMERE", XED_CHIP_WESTMERE},
{"BONNELL", XED_CHIP_BONNELL},
{"SALTWELL", XED_CHIP_SALTWELL},
{"SILVERMONT", XED_CHIP_SILVERMONT},
{"VIA", XED_CHIP_VIA},
{"AMD", XED_CHIP_AMD},
{"GOLDMONT", XED_CHIP_GOLDMONT},
{"GOLDMONT_PLUS", XED_CHIP_GOLDMONT_PLUS},
{"TREMONT", XED_CHIP_TREMONT},
{"SANDYBRIDGE", XED_CHIP_SANDYBRIDGE},
{"IVYBRIDGE", XED_CHIP_IVYBRIDGE},
{"HASWELL", XED_CHIP_HASWELL},
{"BROADWELL", XED_CHIP_BROADWELL},
{"SKYLAKE", XED_CHIP_SKYLAKE},
{"COMET_LAKE", XED_CHIP_COMET_LAKE},
{"SKYLAKE_SERVER", XED_CHIP_SKYLAKE_SERVER},
{"CASCADE_LAKE", XED_CHIP_CASCADE_LAKE},
{"COOPER_LAKE", XED_CHIP_COOPER_LAKE},
{"KNL", XED_CHIP_KNL},
{"KNM", XED_CHIP_KNM},
{"CANNONLAKE", XED_CHIP_CANNONLAKE},
{"ICELAKE", XED_CHIP_ICELAKE},
{"ICELAKE_SERVER", XED_CHIP_ICELAKE_SERVER},
{"TGL", XED_CHIP_TGL},
{"SPR", XED_CHIP_SPR},
{"FUTURE", XED_CHIP_FUTURE},
{"ALL", XED_CHIP_ALL},
{"LAST", XED_CHIP_LAST},
{0, XED_CHIP_LAST},
};

        
xed_chip_enum_t str2xed_chip_enum_t(const char* s)
{
   const name_table_xed_chip_enum_t* p = name_array_xed_chip_enum_t;
   while( p->name ) {
     if (strcmp(p->name,s) == 0) {
      return p->value;
     }
     p++;
   }
        

   return XED_CHIP_INVALID;
}


const char* xed_chip_enum_t2str(const xed_chip_enum_t p)
{
   xed_chip_enum_t type_idx = p;
   if ( p > XED_CHIP_LAST) type_idx = XED_CHIP_LAST;
   return name_array_xed_chip_enum_t[type_idx].name;
}

xed_chip_enum_t xed_chip_enum_t_last(void) {
    return XED_CHIP_LAST;
}
       
/*

Here is a skeleton switch statement embedded in a comment


  switch(p) {
  case XED_CHIP_INVALID:
  case XED_CHIP_I86:
  case XED_CHIP_I86FP:
  case XED_CHIP_I186:
  case XED_CHIP_I186FP:
  case XED_CHIP_I286REAL:
  case XED_CHIP_I286:
  case XED_CHIP_I2186FP:
  case XED_CHIP_I386REAL:
  case XED_CHIP_I386:
  case XED_CHIP_I386FP:
  case XED_CHIP_I486REAL:
  case XED_CHIP_I486:
  case XED_CHIP_PENTIUMREAL:
  case XED_CHIP_PENTIUM:
  case XED_CHIP_QUARK:
  case XED_CHIP_PENTIUMMMXREAL:
  case XED_CHIP_PENTIUMMMX:
  case XED_CHIP_ALLREAL:
  case XED_CHIP_PENTIUMPRO:
  case XED_CHIP_PENTIUM2:
  case XED_CHIP_PENTIUM3:
  case XED_CHIP_PENTIUM4:
  case XED_CHIP_P4PRESCOTT:
  case XED_CHIP_P4PRESCOTT_NOLAHF:
  case XED_CHIP_P4PRESCOTT_VTX:
  case XED_CHIP_CORE2:
  case XED_CHIP_PENRYN:
  case XED_CHIP_PENRYN_E:
  case XED_CHIP_NEHALEM:
  case XED_CHIP_WESTMERE:
  case XED_CHIP_BONNELL:
  case XED_CHIP_SALTWELL:
  case XED_CHIP_SILVERMONT:
  case XED_CHIP_VIA:
  case XED_CHIP_AMD:
  case XED_CHIP_GOLDMONT:
  case XED_CHIP_GOLDMONT_PLUS:
  case XED_CHIP_TREMONT:
  case XED_CHIP_SANDYBRIDGE:
  case XED_CHIP_IVYBRIDGE:
  case XED_CHIP_HASWELL:
  case XED_CHIP_BROADWELL:
  case XED_CHIP_SKYLAKE:
  case XED_CHIP_COMET_LAKE:
  case XED_CHIP_SKYLAKE_SERVER:
  case XED_CHIP_CASCADE_LAKE:
  case XED_CHIP_COOPER_LAKE:
  case XED_CHIP_KNL:
  case XED_CHIP_KNM:
  case XED_CHIP_CANNONLAKE:
  case XED_CHIP_ICELAKE:
  case XED_CHIP_ICELAKE_SERVER:
  case XED_CHIP_TGL:
  case XED_CHIP_SPR:
  case XED_CHIP_FUTURE:
  case XED_CHIP_ALL:
  case XED_CHIP_LAST:
  default:
     xed_assert(0);
  }
*/
