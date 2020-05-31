/*
* File: cfgChecker.c
* Description: Create a cfg using the trace reader
*
*/

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cfgState.h>
#include <cfg.h>
#include <dot.h>

int numThreadsCFG;

Bbl* search(uint64_t addr, Function *walk){
  Function *temp = walk;
  while(temp != NULL){
    Bbl *entry = temp->first;
    Edge *walkEdge = entry->succs;
    while(walkEdge != NULL){
      if(walkEdge->to->first->event.ins.addr == addr){
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
                event = &(succBlock->first->event);
                if(event->ins.addr == addr && compareEventBinary(event, lookFor) == 1){
                    return succBlock;
                }
                else if (event->ins.addr == addr && compareEventBinary(event, lookFor) == 0){ // dynamic mod
                    retBlock = findBlock(succBlock->succs, lookFor);
                    if(retBlock != NULL)
                        return retBlock;        
                }
        }
        succ = succ->next;
    }
    return NULL;
}

int main(int argc, char **argv){
    if(argc != 2) {
      printf("Usage: %s <trace> \n", argv[0]);
      return 1;
    }
    ReaderState *rState = initReader(argv[1], 0);
    ReaderEvent *curEvent = malloc(sizeof(ReaderEvent));
    ReaderEvent *prevEvent = NULL;
    
    numThreadsCFG = (int)getNumThreads(rState);

    cfgState *cfgs = initCFG(rState, numThreadsCFG);
    int mainfound = 0;
    uint64_t stopAddr = 0;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // BUILD CFG
    while(nextEvent(rState, curEvent)) {
        if(curEvent->type == EXCEPTION_EVENT) {
            //printf("EXCEPTION %d\n", curEvent->exception.code);
        }
        else if(curEvent->type == INS_EVENT) {
            //printf("%d %llx %s %s \n", curEvent->ins.tid, (unsigned long long) curEvent->ins.addr, fetchSrcName(&curEvent->ins), fetchFnName(&curEvent->ins));
            if(!mainfound) {
                if(strcmp(fetchStrFromId(rState, curEvent->ins.fnId), "main") == 0) {
                    //printf("Main found\n");
                    mainfound = 1;
                    stopAddr = prevEvent->ins.addr + prevEvent->ins.binSize;
                }
		//printf("not added ");
            }
            if(mainfound) {
                if(curEvent->ins.addr == stopAddr) {
                    break;
                }
                addInstructionToCFG(curEvent, cfgs);
                //printf("%d %"PRIx64 "\n", curEvent->ins.tid, curEvent->ins.addr);
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
    finalizeCFG(cfgs);
    //mkdotfile("../traceSimple/trace.out", cfgs, rState);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Walk till we get to main
    ReaderState *rState2 = initReader(argv[1], 0);
    curEvent = malloc(sizeof(ReaderEvent));

    int mainfoundAgain = 0;
    while(nextEvent(rState2, curEvent)) {
      if(!mainfoundAgain) {
        // Stop reader at main
        if(strcmp(fetchStrFromId(rState, curEvent->ins.fnId), "main") == 0) {
          mainfoundAgain = 1;
          break;
        }
	//printf("not added ");
      }
    }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Now walk step by step in cfg 
    Function *sp = cfgs->startingPhase->startingpoint;
    Bbl *start = sp->first;
    Bbl *curBlock[numThreadsCFG];
    cfgInstruction *prevIns;
    int initial = 0;
    for(initial = 0; initial < numThreadsCFG; initial++){
      curBlock[initial] = NULL;
    }
    curBlock[curEvent->ins.tid] = start;
    cfgInstruction *inst[numThreadsCFG];
    for(initial = 0; initial < numThreadsCFG; initial++){
      inst[initial] = NULL;
    }    
    inst[0] = curBlock[curEvent->ins.tid]->first;
    uint64_t prevEventAddr[numThreadsCFG];
    for(initial = 0; initial < numThreadsCFG; initial++){
      prevEventAddr[initial] = -1;
    }
    int prevEventTid;

    while(checkAllThreads(curBlock)) {

      while(inst[curEvent->ins.tid] != NULL) {
         int curCFGTid = curEvent->ins.tid;
         // Walk through duplicate instructions like REP (pin will duplicate instructions in the trace)
          while(curEvent->ins.addr == prevEventAddr[curEvent->ins.tid]){
            printf("Dup found\n");
            int result = nextEvent(rState2, curEvent);
            printf("After dup, Current Event from TRACE is now: %d %"PRIx64 "\n", curEvent->ins.tid, curEvent->ins.addr);
            // While walking through duplicates, look to see if we find end of trace before end of cfg
            if(inst[curCFGTid]->next != NULL && !(result)){
              fprintf(stderr, "ERROR: Trace terminated, but CFG was at: %"PRIx64 "\n", inst[curEvent->ins.tid]->prev->event.ins.addr);
              return 103;
            }
          }

          ReaderEvent *blockEvent = &(inst[curCFGTid]->event);
         // printf("Order walked through by trace %" PRIx64"\n", curEvent->ins.addr);
          prevEventAddr[curEvent->ins.tid] = curEvent->ins.addr;
          prevIns = inst[curEvent->ins.tid];
          prevEventTid = curEvent->ins.tid;
          if(blockEvent->ins.addr != curEvent->ins.addr) {
              fprintf(stderr, "ERROR: Instruction addresses did not align. Expected: %"PRIx64" tid: %d,  Actual from CFG: %"PRIx64" tid: %d \n", curEvent->ins.addr, curEvent->ins.tid, blockEvent->ins.addr, curEvent->ins.tid);

              printf("ERROR: Instruction addresses did not align. Expected: %"PRIx64" tid: %d,  Actual from CFG: %"PRIx64" tid: %d \n", curEvent->ins.addr, curEvent->ins.tid, blockEvent->ins.addr, curEvent->ins.tid);
              //printf("%d %"PRIx64 "\n", curEvent->ins.tid, curEvent->ins.addr);
              return 102;
          } else {
              printf("Current Event aligns: %d %"PRIx64 " \n", inst[curCFGTid]->event.ins.tid, inst[curCFGTid]->event.ins.addr);
              //printf("Current Event from TRACE: %d %"PRIx64 ", Prev Event from CFG: %d %"PRIx64 " \n", curEvent->ins.tid, curEvent->ins.addr, inst[curCFGTid]->event.ins.tid, inst[curCFGTid]->event.ins.addr);
              cfgInstruction *prevInCFG = inst[curCFGTid];
              inst[curCFGTid] = inst[curCFGTid]->next;
              if(inst[curCFGTid] != NULL){
                printf("Current Event from CFG: %d %"PRIx64 " \n", inst[curCFGTid]->event.ins.tid, inst[curCFGTid]->event.ins.addr);
              } else {
                printf("Null Mark after %"PRIx64 "\n", prevInCFG->event.ins.addr);
              }
          }
          curEvent = malloc(sizeof(ReaderEvent));
          int ret1 = !nextEvent(rState2, curEvent);
          printf("Current Event from Trace %d %"PRIx64 "\n", curEvent->ins.tid, curEvent->ins.addr);
          int ret2 = !(checkAllThreads(curBlock));
          if(ret1 && ret2) {
              // Trace ended but CFG didn't. Is this possible?
              fprintf(stderr, "ERROR: Trace terminated, but CFG was at: %"PRIx64 "\n", inst[curEvent->ins.tid]->prev->event.ins.addr);
              return 103;
          }
      }

      printf("Null Mark leads to finding next block\n"); 

      // If we haven't discovered this thread yet
      if(curBlock[curEvent->ins.tid] == NULL){
        curBlock[curEvent->ins.tid] = search(curEvent->ins.addr, sp);
      } else {
        if(curBlock[curEvent->ins.tid]->first != NULL){
          //printf("Now finding next block from %"PRIx64 " looking for %"PRIx64 "\n", curBlock[curEvent->ins.tid]->last->event.ins.addr, curEvent->ins.addr);
        }
        curBlock[curEvent->ins.tid] = findBlock(curBlock[curEvent->ins.tid]->succs, curEvent);      
      }

      // We ran out of edges which means we didn't
      // find a child, so error out.
      if(curBlock[curEvent->ins.tid] == NULL) {
          if(curEvent->ins.addr == stopAddr) {
              break;
          }
          if(prevIns->block->fun->exit->succs == NULL){
              break;
          }
          fprintf(stderr, "ERROR: Unable to find next address in cfg traversal. Event address %" PRIx64" was not found. prev event addr: %" PRIx64"\n", curEvent->ins.addr, prevEventAddr[curEvent->ins.tid]);
          return 104;
      }

      inst[curEvent->ins.tid] = curBlock[curEvent->ins.tid]->first;
      
    }
    //validateCFG(cfgs);
    return(0);
}
