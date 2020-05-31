/*
* File: cfgChecker.c
* Description: Create a cfg using the trace reader
*
*/

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cfg.h>
#include <dot.h>
#include "BlockQueue.h"
#include "validateCFG.h"

int numThreadsCFG;

Bbl* search(uint64_t addr, Function *walk){
  Function *temp = walk;
  while(temp != NULL){
    Bbl *entry = temp->first;
    Edge *walkEdge = entry->succs;
    while(walkEdge != NULL){
      if(walkEdge->to->first->event->ins.addr == addr){
        return(walkEdge->to);
      }
      walkEdge = walkEdge->next;
    }
    temp = temp->next;
  }
  return(NULL);
}


int checkAllThreads(Bbl **curBlk){
  int i;
  for(i = 0; i < numThreadsCFG; i++){
    if(curBlk[i] != NULL){
      return(1);
    }
  }
  return(0);
}

int compareEventBinary(ReaderEvent *event, ReaderEvent *lookFor){
  // If binary sizes don't match, then  the two are not the same instruction
  if(event->ins.binSize != lookFor->ins.binSize){
    return(0);
  }
  // Otherwise walk through binary to compare
  uint8_t *bytesOne = event->ins.binary;
  uint8_t *bytesTwo = lookFor->ins.binary;
  int i = 0;
  for(i = 0; i < event->ins.binSize; i++){
    if(bytesOne[i] != bytesTwo[i]){
      return(0);
    }
  }
  return(1);

}

Bbl* findBlock(Edge *succ, ReaderEvent *lookFor) {
    while(succ != NULL) {
        uint64_t addr = lookFor->ins.addr;
        Bbl *retBlock = NULL;
        ReaderEvent *event = NULL;
        Bbl* succBlock = succ->to;
        switch (succBlock->btype){
            case BT_UNKNOWN:
            case BT_ENTRY:
            case BT_EXIT:
                retBlock = findBlock(succBlock->succs, lookFor);
                if(retBlock != NULL)
                    return retBlock;
                break;
            default:
                event = (succBlock->first->event);
                if(event->ins.addr == addr && compareEventBinary(event, lookFor) == 1)
                    return succBlock;
        }
        succ = succ->next;
    }
    return NULL;
}

int main(int argc, char **argv){
    if(argc != 3) {
      printf("Usage: %s <trace> <number of threads>\n", argv[0]);
      return 1;
    }
    initReader(argv[1], 0);
    ReaderEvent *curEvent = malloc(sizeof(ReaderEvent));
    ReaderEvent *prevEvent = NULL;
    
    cfg *cfgs = malloc(sizeof(cfg));
    numThreadsCFG = atoi(argv[2]);

    initCFG(cfgs, numThreadsCFG);
    int mainfound = 1;
    uint64_t stopAddr = 0;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // BUILD CFG
    while(nextEvent(curEvent)) {
        if(curEvent->type == EXCEPTION_EVENT) {
            printf("EXCEPTION %d\n", curEvent->exception.code);
        }
        else if(curEvent->type == INS_EVENT) {
            //printf("%d %llx %s %s ", curEvent->ins.tid, (unsigned long long) curEvent->ins.addr, fetchSrcName(&curEvent->ins), fetchFnName(&curEvent->ins));
            if(!mainfound) {
                if(strcmp(fetchFnName(&(curEvent->ins)), "main") == 0) {
                    printf("Main found\n");
                    mainfound = 1;
                    stopAddr = prevEvent->ins.addr + prevEvent->ins.binSize;
                }
		//printf("not added ");
            }
            if(mainfound) {
                if(curEvent->ins.addr == stopAddr) {
                    break;
                }
                addInstructionToCFG(curEvent);
                //printf("a%d %"PRIx64 "\n", curEvent->ins.tid, curEvent->ins.addr);
		//printf("Order added into cfg construction %" PRIx64" \n", curEvent->ins.addr);
            }
            //printf("%s\n", info.mnemonic);
        }
        else {
            printf("UNKNOWN EVENT TYPE\n");
        }
        prevEvent = curEvent;
        curEvent = malloc(sizeof(ReaderEvent));
    }
    closeCFG();
    mkdotfile("../traceSimple/trace.out", cfgs);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Walk till we get to main
    initReader(argv[1], 0);
    curEvent = malloc(sizeof(ReaderEvent));

    int mainfoundAgain = 0;
    while(nextEvent(curEvent)) {
      if(!mainfoundAgain) {
        // Stop reader at main
        if(strcmp(fetchFnName(&(curEvent->ins)), "main") == 0) {
          mainfoundAgain = 1;
          break;
        }
	//printf("not added ");
      }
    }
    while(!nextEvent(curEvent) && !(checkAllThreads(curBlock))) {
        //printf("Order walked %" PRIx64" \n", curEvent->ins.addr);
        if(curEvent->ins.addr == stopAddr){
          return(0);
        }
        prevEvent = curEvent;
        curEvent = malloc(sizeof(ReaderEvent));
    }
    return(0);
}

