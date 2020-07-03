/*
 * File: parser.h
 * Purpose: Definitions related to the file parser.c
 */

#ifndef __PARSER_H__
#define __PARSER_H__

#include "main.h"

typedef enum {
  END = -1,
  ARGNUM,
  INTCONST,
  ADD,
  SUB,
  MUL,
  DIV,
  LPAREN,
  RPAREN
} TokenType;

/*
 * struct tn: AST nodes
 */
typedef struct tn {
  TokenType ntype;
  int val;                       /* used for ARGNUM and INTCONST nodes */
  struct tn *child0, *child1;    /* used for ADD, SUB, MUL, DIV */  
} TreeNode;

TreeNode *parse(char *s);
uint64_t eval(TreeNode *t, FnTracer_State *f_state, int tid);

#endif    /* __PARSER_H__ */
