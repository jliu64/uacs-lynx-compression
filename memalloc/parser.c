/*
 * File: parser.c
 * Purpose: A parser for a simple grammar for expressions to compute
 *    allocation sizes.
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include "parser.h"
#include "process_trace.h"
#include "utils.h"

/*
 * expression grammar for argument values:
 *
 *    exp ::=  exp + exp 
 *         |   exp - exp
 *         |   exp * exp
 *         |   exp / exp
 *         |   ( exp )
 *         |   int_const
 *         |   $n
 *
 */

/*******************************************************************************
 *                                                                             *
 *                                 PROTOTYPES                                  *
 *                                                                             *
 *******************************************************************************/

static int tok_val;
static char *ptr = NULL;   /* points into the string to be parsed */
static TokenType next_token();
static TokenType curr_tok;
static TreeNode *expr();
static TreeNode *term();
static TreeNode *factor();

/*******************************************************************************
 *                                                                             *
 * parse() -- parses the expression string s and returns a pointer to its AST. *
 *                                                                             *
 * For recursive descent parsing, we use the following grammar, which is       *
 * equivalent to the grammar shown above:                                      *
 *                                                                             *
 *    expr ::= term exp1                                                       *
 *    exp1 ::= + term exp1  |  - term exp1  |  epsilon                         *
 *                                                                             *
 *    term ::= factor term1                                                    *
 *    term1 ::= * factor term1  |  / factor term1  |  epsilon                  *
 *                                                                             *
 *    factor ::= ( expr )  |  int_const  |  arg                                *
 *                                                                             *
 *******************************************************************************/

TreeNode *expr() {
  TreeNode *root, *t0;

  root = term();

  while (curr_tok == ADD || curr_tok == SUB) {
    t0 = alloc(sizeof(TreeNode));
    t0->ntype = curr_tok;
    t0->child0 = root;

    curr_tok = next_token();
    t0->child1 = term();

    root = t0;
    curr_tok = next_token();
  }

  return root;
}

TreeNode *term() {
  TreeNode *root, *t0;

  root = factor();
  
  curr_tok = next_token();
  while (curr_tok == MUL || curr_tok == DIV) {
    t0 = alloc(sizeof(TreeNode));
    t0->ntype = curr_tok;
    t0->child0 = root;

    curr_tok = next_token();
    t0->child1 = factor();
    
    root = t0;
    curr_tok = next_token();
  }

  return root;
}

TreeNode *factor() {
  TreeNode *t0 = NULL;

  if (curr_tok == LPAREN) {
    curr_tok = next_token();
    t0 = expr();
    if (curr_tok == RPAREN) {
      curr_tok = next_token();
    }
    else {
      fprintf(stderr, "[%s] Syntax error: curr_tok = %d at %s\n",
	      __func__, curr_tok, ptr);
    }
  }
  else if (curr_tok == ARGNUM || curr_tok == INTCONST) {
    t0 = alloc(sizeof(TreeNode));
    t0->ntype = curr_tok;
    t0->val = tok_val;
  }
  else {
    fprintf(stderr, "[%s] Syntax error: curr_tok = %d at %s\n",
	    __func__, curr_tok, ptr);
  }

  return t0;
}


static void print_ast_0(TreeNode *t) {
  if (t == NULL) {
    printf("(null)");
    return;
  }
  
  switch (t->ntype) {
  case ARGNUM: printf(" arg#%d ", t->val); break;
  case INTCONST: printf(" %d ", t->val); break;
  case ADD: 
  case SUB: 
  case MUL:
  case DIV:
    printf("( ");
    print_ast_0(t->child0);
    if (t->ntype == ADD) {
      printf("+");
    }
    else if (t->ntype == SUB) {
      printf("-");
    }
    else if (t->ntype == MUL) {
      printf("*");
    }
    else if (t->ntype == DIV) {
      printf("/");
    }
    print_ast_0(t->child1);
    printf(") ");
    break;
  default:
    fprintf(stderr, "Unrecognized node type: %d\n", t->ntype);
  }

}

void print_ast(TreeNode *t) {
  print_ast_0(t);
  printf("\n");
}


/*******************************************************************************
 *                                                                             *
 *                        next_token() -- the tokenizer                        *
 *                                                                             *
 *******************************************************************************/

static TokenType next_token() {
  int i;
  TokenType token;
  
  assert(ptr != NULL);

  /* skip whitespace */
  while (*ptr != '\0' && isspace(*ptr)) {
    ptr++; 
  }

  if (*ptr == '\0') {
    return END;
  }

  if (*ptr == '$') {  /* function argument: $n */
    ptr++; 
    i = tok_val = 0;
    while (*ptr != '\0'&& *ptr >= '0' && *ptr < '9') {
      tok_val = tok_val * 10 + (*ptr - '0');
      ptr++; 
      i++;
    }
    
    if (i == 0) {
      fprintf(stderr, "ERROR near %c\n", *ptr);
    }

    return ARGNUM;
  }
  else if (*ptr >= '0' && *ptr <= '9') {
    tok_val = 0;
    while (*ptr != '\0'&& *ptr >= '0' && *ptr < '9') {
      tok_val = tok_val * 10 + (*ptr - '0');
      ptr++; 
    }
    
    return INTCONST;
  }
  else {
    switch (*ptr) {
    case '+': token = ADD; break;
    case '-': token = SUB; break;
    case '*': token = MUL; break;
    case '/': token = DIV; break;
    case '(': token = LPAREN; break;
    case ')': token = RPAREN; break;
    default:
      fprintf(stderr, "ERROR near %c\n", *ptr);
      token = END;
    }
    ptr++; 
    return token;
  }
}


/*******************************************************************************
 *                                                                             *
 * parse(s) -- the top-level interface to the parser.  The argument s is the   *
 * string to be parsed.                                                        *
 *                                                                             *
 *******************************************************************************/

TreeNode *parse(char *s) {
  TreeNode *ast;
  
  ptr = s;
  curr_tok = next_token();
  ast = expr();
  curr_tok = next_token();
  if (curr_tok != END) {
    fprintf(stderr, "[%s] Syntax error [curr_tok = %d at %s]\n",
	    __func__, curr_tok, ptr);
  }

  return ast;
}


/*******************************************************************************
 *                                                                             *
 * eval() -- evaluate an AST in a given state                                  *
 *                                                                             *
 *******************************************************************************/

uint64_t eval(TreeNode *t, FnTracer_State *f_state, int tid) {
  uint64_t val = 0, val0, val1;

  assert(t != NULL);

  switch (t->ntype) {
  case ARGNUM:
    return fn_arg_val(t->val, f_state, tid);

  case INTCONST:
    return t->val;
    
  case ADD: 
  case SUB: 
  case MUL:
  case DIV:
    val0 = eval(t->child0, f_state, tid);
    val1 = eval(t->child1, f_state, tid);
    
    if (t->ntype == ADD) {
      val = val0 + val1;
    }
    else if (t->ntype == SUB) {
      val = val0 - val1;
    }
    else if (t->ntype == MUL) {
      val = val0 * val1;
    }
    else if (t->ntype == DIV) {
      val = val0 / val1;
    }
    return val;
    
  default:
    fprintf(stderr, "Unrecognized node type: %d\n", t->ntype);
    exit(1);
  }

  return 0;    /* NOTREACHED */
}

