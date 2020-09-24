/// @file xed-operand-width-enum.h

// This file was automatically generated.
// Do not edit this file.

#if !defined(XED_OPERAND_WIDTH_ENUM_H)
# define XED_OPERAND_WIDTH_ENUM_H
#include "xed-common-hdrs.h"
typedef enum {
  XED_OPERAND_WIDTH_INVALID,
  XED_OPERAND_WIDTH_ASZ,
  XED_OPERAND_WIDTH_SSZ,
  XED_OPERAND_WIDTH_PSEUDO,
  XED_OPERAND_WIDTH_PSEUDOX87,
  XED_OPERAND_WIDTH_A16,
  XED_OPERAND_WIDTH_A32,
  XED_OPERAND_WIDTH_B,
  XED_OPERAND_WIDTH_D,
  XED_OPERAND_WIDTH_I8,
  XED_OPERAND_WIDTH_U8,
  XED_OPERAND_WIDTH_I16,
  XED_OPERAND_WIDTH_U16,
  XED_OPERAND_WIDTH_I32,
  XED_OPERAND_WIDTH_U32,
  XED_OPERAND_WIDTH_I64,
  XED_OPERAND_WIDTH_U64,
  XED_OPERAND_WIDTH_F16,
  XED_OPERAND_WIDTH_F32,
  XED_OPERAND_WIDTH_F64,
  XED_OPERAND_WIDTH_DQ,
  XED_OPERAND_WIDTH_XUB,
  XED_OPERAND_WIDTH_XUW,
  XED_OPERAND_WIDTH_XUD,
  XED_OPERAND_WIDTH_XUQ,
  XED_OPERAND_WIDTH_X128,
  XED_OPERAND_WIDTH_XB,
  XED_OPERAND_WIDTH_XW,
  XED_OPERAND_WIDTH_XD,
  XED_OPERAND_WIDTH_XQ,
  XED_OPERAND_WIDTH_ZB,
  XED_OPERAND_WIDTH_ZW,
  XED_OPERAND_WIDTH_ZD,
  XED_OPERAND_WIDTH_ZQ,
  XED_OPERAND_WIDTH_MB,
  XED_OPERAND_WIDTH_MW,
  XED_OPERAND_WIDTH_MD,
  XED_OPERAND_WIDTH_MQ,
  XED_OPERAND_WIDTH_M64INT,
  XED_OPERAND_WIDTH_M64REAL,
  XED_OPERAND_WIDTH_MEM108,
  XED_OPERAND_WIDTH_MEM14,
  XED_OPERAND_WIDTH_MEM16,
  XED_OPERAND_WIDTH_MEM16INT,
  XED_OPERAND_WIDTH_MEM28,
  XED_OPERAND_WIDTH_MEM32INT,
  XED_OPERAND_WIDTH_MEM32REAL,
  XED_OPERAND_WIDTH_MEM80DEC,
  XED_OPERAND_WIDTH_MEM80REAL,
  XED_OPERAND_WIDTH_F80,
  XED_OPERAND_WIDTH_MEM94,
  XED_OPERAND_WIDTH_MFPXENV,
  XED_OPERAND_WIDTH_MXSAVE,
  XED_OPERAND_WIDTH_MPREFETCH,
  XED_OPERAND_WIDTH_P,
  XED_OPERAND_WIDTH_P2,
  XED_OPERAND_WIDTH_PD,
  XED_OPERAND_WIDTH_PS,
  XED_OPERAND_WIDTH_PI,
  XED_OPERAND_WIDTH_Q,
  XED_OPERAND_WIDTH_S,
  XED_OPERAND_WIDTH_S64,
  XED_OPERAND_WIDTH_SD,
  XED_OPERAND_WIDTH_SI,
  XED_OPERAND_WIDTH_SS,
  XED_OPERAND_WIDTH_V,
  XED_OPERAND_WIDTH_Y,
  XED_OPERAND_WIDTH_W,
  XED_OPERAND_WIDTH_Z,
  XED_OPERAND_WIDTH_SPW8,
  XED_OPERAND_WIDTH_SPW,
  XED_OPERAND_WIDTH_SPW5,
  XED_OPERAND_WIDTH_SPW3,
  XED_OPERAND_WIDTH_SPW2,
  XED_OPERAND_WIDTH_I1,
  XED_OPERAND_WIDTH_I2,
  XED_OPERAND_WIDTH_I3,
  XED_OPERAND_WIDTH_I4,
  XED_OPERAND_WIDTH_I5,
  XED_OPERAND_WIDTH_I6,
  XED_OPERAND_WIDTH_I7,
  XED_OPERAND_WIDTH_VAR,
  XED_OPERAND_WIDTH_BND32,
  XED_OPERAND_WIDTH_BND64,
  XED_OPERAND_WIDTH_PMMSZ16,
  XED_OPERAND_WIDTH_PMMSZ32,
  XED_OPERAND_WIDTH_QQ,
  XED_OPERAND_WIDTH_YUB,
  XED_OPERAND_WIDTH_YUW,
  XED_OPERAND_WIDTH_YUD,
  XED_OPERAND_WIDTH_YUQ,
  XED_OPERAND_WIDTH_Y128,
  XED_OPERAND_WIDTH_YB,
  XED_OPERAND_WIDTH_YW,
  XED_OPERAND_WIDTH_YD,
  XED_OPERAND_WIDTH_YQ,
  XED_OPERAND_WIDTH_YPS,
  XED_OPERAND_WIDTH_YPD,
  XED_OPERAND_WIDTH_ZBF16,
  XED_OPERAND_WIDTH_VV,
  XED_OPERAND_WIDTH_ZV,
  XED_OPERAND_WIDTH_WRD,
  XED_OPERAND_WIDTH_MSKW,
  XED_OPERAND_WIDTH_ZMSKW,
  XED_OPERAND_WIDTH_ZF32,
  XED_OPERAND_WIDTH_ZF64,
  XED_OPERAND_WIDTH_ZUB,
  XED_OPERAND_WIDTH_ZUW,
  XED_OPERAND_WIDTH_ZUD,
  XED_OPERAND_WIDTH_ZUQ,
  XED_OPERAND_WIDTH_ZI8,
  XED_OPERAND_WIDTH_ZI16,
  XED_OPERAND_WIDTH_ZI32,
  XED_OPERAND_WIDTH_ZI64,
  XED_OPERAND_WIDTH_ZU8,
  XED_OPERAND_WIDTH_ZU16,
  XED_OPERAND_WIDTH_ZU32,
  XED_OPERAND_WIDTH_ZU64,
  XED_OPERAND_WIDTH_ZU128,
  XED_OPERAND_WIDTH_LAST
} xed_operand_width_enum_t;

/// This converts strings to #xed_operand_width_enum_t types.
/// @param s A C-string.
/// @return #xed_operand_width_enum_t
/// @ingroup ENUM
XED_DLL_EXPORT xed_operand_width_enum_t str2xed_operand_width_enum_t(const char* s);
/// This converts strings to #xed_operand_width_enum_t types.
/// @param p An enumeration element of type xed_operand_width_enum_t.
/// @return string
/// @ingroup ENUM
XED_DLL_EXPORT const char* xed_operand_width_enum_t2str(const xed_operand_width_enum_t p);

/// Returns the last element of the enumeration
/// @return xed_operand_width_enum_t The last element of the enumeration.
/// @ingroup ENUM
XED_DLL_EXPORT xed_operand_width_enum_t xed_operand_width_enum_t_last(void);
#endif
