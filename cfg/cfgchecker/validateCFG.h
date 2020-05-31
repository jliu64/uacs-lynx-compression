/* File: validateCFG.h
 * Author: Theodore Sackos
 * Purpose: Define the prototypes for functions to verify
 * the integrity of the CFG tool's internal structure.
 */

#include "../cfg/cfg.h"
#include "BlockQueue.h"

#ifndef VALIDATECFG_H_
#define VALIDATECFG_H_

void validateCFG(cfg *root);

/* Made Static: 
 * void validateFunction(Function *function);
 * void traverseBlocks(Bbl *block);
 * void validateBlock   (Bbl *block);
 */

#endif
