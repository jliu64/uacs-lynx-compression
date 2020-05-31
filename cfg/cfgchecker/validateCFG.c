/* File: validateCFG.c
 * Author: Theodore Sackos
 * Purpose: This file defines functions that perform integrity checking 
 * of the CFG tool's internal structure. After the construction of a cfg
 * is complete, users may pass the root of that cfg to validateCFG() and
 * these functions will report an error to stderr and exit with the exit
 * status of 1 if any invariant of the structure of the cfg fails. The
 * current supported checks are as follows: 
 *
 * Invariant 1:     Every block has a list of successors, each of the 
 * blocks in that list has a list of predecessors. Given a block B, 
 * where B is the parent block of A, if A is in the successor list of 
 * B, then B should be in the predecessor list of A.
 *
 * Invariant 2:     Each function belongs to a list of functions. If 
 * Function A->next is Function B then B->prev should always be A.
 *
 * Invariant 3:     Each block belongs to a list of blocks within a function. 
 * If Basic Block A->next is Basic Block B then B->prev should always be A. 
 */

#include "validateCFG.h"

static void validateFunction(Function *function);
static void traverseBlocks(Bbl *block);
static void validateBlock(Bbl *block);

/* Queue for traversing a function */
Queue *lwall = NULL,
      *rwall = NULL;

/* Queue to keep track of visited blocks in a function */
Queue *visitStart = NULL, 
      *visitEnd   = NULL;

int QueueSize; // Length of traversal queue      - excludes dummy nodes
int VisitSize; // Length of marked visited queue - excludes dummy nodes

int DEBUG = 1;

/* 
 * validateCFG(cfg *root) -- Silent pass as if assertion. Loudly fails.
 *
 * Given the root of a cfg, perform a breath first search through all 
 * functions enforcing the following invariants:
 */
void validateCFG(cfg *root){
    lwall      = initQ(&rwall);    // Initialize queue for breadth first traversal
    visitStart = initQ(&visitEnd); // Initialize queue for visited blocks

    Function *function;
    for (function = root->startingpoint; function != NULL; function = function->next) {
        validateFunction(function);    
    }

    /* Silence is bliss - Assertions pass when validate is silent */
    return;
}

/* validateFunction(Function *) -- Traverse the function passed a an
 * argument and explicitly enfore invariant 2. If invariant 2 fails
 * for any function, report an error to stderr and exit with exit
 * status 1.
 *
 * This function calls traverseBlocks() to enfore invariant 1 and 3. 
 */
static void validateFunction(Function *function){
    Edge *e;
    for(e = function->first->preds; e!= NULL; e = e->next){    
        if(DEBUG)
            fprintf(stderr, "Checking function at %p\n", function);
            
        /* Check invariants 1 and 3 */
        traverseBlocks(e->to);
    }
        
    /* Check invariant 2 */
    if(function->next->prev != function){
        fprintf(stderr, "Invariant 2 failed for function A->id = %d and function B->id = %d\n", 
                function->id, 
                function->next->id);
        exit(1);
    }
}

/* traverseBlocks(Bbl *block) -- Given the entry pseudoblock to
 * a function, do a breath-first traversal of the function this
 * block starts. For each block traversed, enforce the 3rd 
 * invariant explicitly. If the 3rd invariant fails, report an
 * error to stderr and exit with exit status 1. 
 * 
 * This function calls validateBlock() to enfore the 1st invariant.
 * Assumes block is an entry pseudo-block to a function.
 */
static void traverseBlocks(Bbl *block){
    assert(block->btype == BT_ENTRY);
    Edge *entry;
    for(entry = block->succs; entry != NULL; entry = entry->next){
        enqueue(entry->to, lwall, rwall);
        QueueSize++;
    }

    Bbl *cur;
    while(QueueSize > 0){
        
        if(DEBUG)
            printf("\n");

        cur = dequeue(lwall, rwall);
        QueueSize--;

        /* Check Invariant 3 - Block Next/Prev integrity */ 
        if(cur != cur->next->prev){
            fprintf(stderr, "Invariant 3 failed for block A:%d and block B:%d\n", cur->id, cur->next->id);
            exit(1);
        } 
        
        validateBlock(cur);

        /* For each successor of the current block, if it has not yet been visited
         * mark it visited by adding it to the visit queue then add it to the lwall
         * queue to be traversed */
        Edge *e;
        for(e = cur->succs; e != NULL; e = e->next){
            Bbl *nextBlock = e->to;
            if(!Qcontains(nextBlock, visitStart, visitEnd)){
                
                /* Add block to visit queue */
                enqueue(nextBlock, visitStart, visitEnd);
                VisitSize++;

                /* We want to stop when we reach the exit pseudoblock */
                if(nextBlock->btype != BT_EXIT){
                    enqueue(nextBlock, lwall, rwall);
                    QueueSize++;
                }
            }
        }
    }

    /* Invariant 1 holds for this function, return to caller */
    return;
}
/* validateBlock(Bbl *block) -- block is a basic block that we want to check.
 * We will call this block the "block being investigated". The investigated 
 * block has all of its successors checked for the invariant that they each
 * contain the investigated block in its predecessor list. If it does not, 
 * report an error to srderr and exit. 
 */
static void validateBlock(Bbl *block){
    Edge *succEdge, // Successor Edges of the block being investigated
         *predEdge; // Predecessor Edges of the successor being investigated

    char invariantHolds;
    for(succEdge = block->succs; succEdge != NULL; succEdge = succEdge->next){ 

        /* The current successor being investigated */
        Bbl *curSucc = succEdge->to;
        invariantHolds = 0;
        
        /* Check that invariant 1 holds. For every successor B of block A
         * we should find that A is a predecessor of B */
        for(predEdge = curSucc->preds; predEdge != NULL; predEdge = predEdge->next){
            if(predEdge->from == block){ //TODO: Why is this predEdge->from and not predEdge->to?
                invariantHolds = 1;
                break;
            }
        }
        
        /* If the invariant failed to hold report it and exit */
        if(!invariantHolds){
            printf("Invariant 1 fails for block %d and its successor %d\n", block->id, curSucc->id);
            exit(1);
        }
    }

    /* Invariant 1 holds, return to caller */
    return;
}

