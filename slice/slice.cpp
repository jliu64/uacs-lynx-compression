/*
* File: sliceDriver.c
* Description: TODO: Create slice.
*
*/

// Includes for the cfg construction code
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <list>
#include <map>
#include <string>
#include <cassert>
#include <unordered_set>
#include <algorithm>
#include <utility>
#include <chrono>
#include <iostream>
#include "slice.h"
#include "sliceState.h"
#include <libgen.h>
#include <xed-interface.h>
#include <xed-iclass-enum.h>
#include "utils.h"

using namespace std;
using namespace std::chrono;
using std::vector;
using std::unordered_set;

extern "C" {
    #include "../shared/LynxReg.h"
    #include <Reader.h>
    #include <Taint.h>
    #include <cfg.h>
    #include <cfgAPI.h>
    #include <cfgState.h>
    #include <controlTransfer.h>
}

//SLICE CODE

/*
 *  Function: getActionAtIndex
 *  Purpose: Return action at given index from trace
 */
Action *getActionAtIndex(SliceState *slice, uint64_t index){
  return(slice->listOfActions[index]);
}

uint64_t getAddrFromAction(Action *action){
  if(action->instruction->event.type == EXCEPTION_EVENT){
    return(action->instruction->event.exception.addr);
  }
  return(action->instruction->event.ins.addr);
}

/*
*  Function: isCmp
*  Purpose: Determine if an x86 instruction is a test/cmp instruction
*/
int isCmp(Action *action){
  xed_iclass_enum_t inst = action->curInfo->insClass;
  cfgInstruction *instruction = action->instruction;
  return(instruction->event.type == INS_EVENT && (inst == XED_ICLASS_TEST || inst == XED_ICLASS_CMP));
}

/*
*  Function: getBlockSlice
*  Purpose: Given a action, use the action's cfg pointer to get the single block that 
*           holds all the actions
*/
blockSlice *getBlockSlice(SliceState *slice, Action *action){
  if(slice->htableslice.find(action->instruction) != slice->htableslice.end()){
    return(slice->htableslice.find(action->instruction)->second);
  }
  return NULL;
}

/*
*  Function: createNewBlock
*  Purpose: Make a new Korel-block for a given set of indicies
*/
blockSlice *createNewBlock(SliceState *slice, uint64_t startPos, uint64_t endPos, uint64_t id){
  //blockSlice *bbl = (blockSlice *)malloc(sizeof(blockSlice));
  blockSlice *bbl = new blockSlice();
  bbl->start = startPos;
  bbl->end = endPos;
  bbl->id = id;
  assert(getActionAtIndex(slice, startPos)->tid == getActionAtIndex(slice, endPos)->tid);
  uint32_t tid = getActionAtIndex(slice, startPos)->tid;
  uint64_t i;
  for(i = startPos; i <= endPos; i++){
    if(getActionAtIndex(slice, i)->tid != tid){
      continue;
    }
    // Update action's block pointer
    getActionAtIndex(slice, i)->bbl = bbl;
    // Update block's collection of actions
    bbl->actionsSet.insert(i);
    // We use an actions cfgInstruction pointer to map to that action's block
    slice->htableslice[getActionAtIndex(slice, i)->instruction] = bbl;
  }
  return(bbl);
}

uint64_t getNextOfSameThread(SliceState *slice, uint64_t pos, uint32_t tid){
  while((pos < slice->numActions) && (getActionAtIndex(slice, pos)->tid != tid)){
    pos++;
  }
  return pos;
}

bool isCmpJumpBlock(SliceState *slice, uint64_t pos){
  uint64_t numActions = slice->numActions;
  bool isACmp = isCmp(getActionAtIndex(slice, pos));
  bool isInRange = (pos+1 < numActions); 
  if(!isInRange || !isACmp){
    return false;
  }
  uint64_t nextThreadInsPos = getNextOfSameThread(slice, pos+1, getActionAtIndex(slice, pos)->tid);
  if(nextThreadInsPos >= numActions){
    return false;
  }
  bool nextInsInThreadIsJump = isConditionalJump(getActionAtIndex(slice, nextThreadInsPos)->curInfo->insClass);
  return(isACmp && nextInsInThreadIsJump);
}

bool brokenCompJumpBlock(SliceState *slice, uint64_t pos){
  bool firstHalfSeen = (getBlockSlice(slice, getActionAtIndex(slice, pos)) != NULL && isCmp(getActionAtIndex(slice, pos)));
  if(!firstHalfSeen){ // bail out early
    return false;
  }
  blockSlice *nextJmpBBLInThread = getBlockSlice(slice, getActionAtIndex(slice, getNextOfSameThread(slice, pos+1, getActionAtIndex(slice, pos)->tid)));
  bool secondHalfNotSeen = (firstHalfSeen && nextJmpBBLInThread == NULL);
  bool secondHalfIsNotMatch = (secondHalfNotSeen || (getBlockSlice(slice, getActionAtIndex(slice, pos)) != nextJmpBBLInThread));
  return(secondHalfIsNotMatch);
}

/*
*  Function: buildBlocks
*  Purpose: For a given collection of actions, build a list of blocks with those actions
*/
void buildBlocks(SliceState *slice){
  // Build list of blocks from list of actions
  uint64_t numActions = slice->numActions;
  uint64_t i, blockCounter;
  for(i = 0, blockCounter = 0; i < numActions; i++){
    // Two cases to handle. Either we have created a block for the action(s) and should just update or still need to create a new block
    // CASE 1: Create a new block: two types of blocks (normal 1 ins block or cmp + jmp block)
    //         The second type of block is trickier to tell (i.e. both actions must been seen to update em)
    if(getBlockSlice(slice, getActionAtIndex(slice, i)) == NULL || brokenCompJumpBlock(slice, i)){ // If we haven't seen this block before
      // If-goto block (actions at i,i+1 go into one block)
      if(isCmpJumpBlock(slice, i)){
        uint64_t nextJump = getNextOfSameThread(slice, i+1, getActionAtIndex(slice, i)->tid);
        blockSlice *bbl = createNewBlock(slice, i, nextJump, blockCounter);
        slice->removableBlocks.insert(bbl);
        // Small Opt: if both cmp/jmp instructions in same thread then can skip looking at next ins
        if(i+1 == nextJump){
          i++; // Just inserted two actions into our block
        }
      } 
      // Regular block (1 instruction for now)
      else {
        blockSlice *bbl = createNewBlock(slice, i, i, blockCounter);
        slice->removableBlocks.insert(bbl);
      }
      blockCounter++;
    } else { // We've seen this block before, update which actions are in that block
      // cmp + jump block (when we've seen both before IN SAME BLOCK)
      if(isCmpJumpBlock(slice, i)){
        // Add the compare
        uint64_t nextJump = getNextOfSameThread(slice, i+1, getActionAtIndex(slice, i)->tid);
        getBlockSlice(slice, getActionAtIndex(slice, i))->actionsSet.insert(i);
        getActionAtIndex(slice, i)->bbl = getBlockSlice(slice, getActionAtIndex(slice, i));
        // Then update the jmp
        getBlockSlice(slice, getActionAtIndex(slice, nextJump))->actionsSet.insert(nextJump);
        getActionAtIndex(slice, nextJump)->bbl = getBlockSlice(slice, getActionAtIndex(slice, nextJump));
        // Small Opt: if both cmp/jmp instructions in same thread then can skip looking at next ins
        if(i+1 == nextJump){
          i++; // Just inserted two actions into our block
        }
      } 
      // Otherwise standard action that we've seen/built a block for before
      else {
        getBlockSlice(slice, getActionAtIndex(slice, i))->actionsSet.insert(i);
        getActionAtIndex(slice, i)->bbl = getBlockSlice(slice, getActionAtIndex(slice, i));
      }
    }
  }
}

void setAllNotMarkedOrVisited(SliceState *slice){
  uint64_t numActions = slice->numActions;
  uint64_t i;
  for(i = 0; i < numActions; i++){
    getActionAtIndex(slice, i)->visited = 0;
    getActionAtIndex(slice, i)->marked = 0;
  }
}

uint8_t isPushIns(xed_iclass_enum_t inst){
  uint8_t res = (inst == XED_ICLASS_PUSH || inst == XED_ICLASS_PUSHA || inst == XED_ICLASS_PUSHAD || inst == XED_ICLASS_PUSHF || inst == XED_ICLASS_PUSHFD || inst == XED_ICLASS_PUSHFQ);
  return res;
}

uint8_t isPopIns(xed_iclass_enum_t inst){
  uint8_t res = (inst == XED_ICLASS_POP || inst == XED_ICLASS_POPA || inst == XED_ICLASS_POPAD || inst == XED_ICLASS_POPF || inst == XED_ICLASS_POPFD || inst == XED_ICLASS_POPFQ || inst == XED_ICLASS_POPCNT);
  return res;
}

void collectLastDefinitionsUsingCurAction(TaintState *backTaint, Action *curAction, std::map<uint64_t, Action *> &mapLabelToAction, uint8_t keepReg){
  // Forward Propagate any taint
  uint64_t taint = propagateForward(backTaint, &(curAction->instruction->event), curAction->curInfo, keepReg);
  // Walk through all labels to find last definitions
  uint64_t size = labelSize(backTaint, taint);
  //printf("Label size is %ld\n", size);
  uint64_t *labelsInTaint = getSubLabels(backTaint, taint);
  for(uint64_t i = 0; i < size; i++){
    uint64_t label = labelsInTaint[i];
    //printf("Found label %ld in label %ld returned from backwards propagate\n", label, taint);
    
    if(mapLabelToAction.find(label) != mapLabelToAction.end()){
      //printf("Found a last definition from label %ld. %lx is a last def of  %lx\n", label, mapLabelToAction[label]->instruction->event.ins.addr, curAction->instruction->event.ins.addr);
      Action *found = mapLabelToAction[label];

      // For PUSH, look for reg last def
      if(isPushIns(curAction->curInfo->insClass)){
        uint64_t regLabel = 0;
        regLabel = getCombinedRegTaint(backTaint, curAction->reg, curAction->tid, regLabel);
        if(regLabel == label){
          //printf("Found REG label for our PUSH!, %ld %ld\n", regLabel, label);
          curAction->lastDefForRegOnPush = found;
        }
      }
      // For POP, set up the bypass last def
      if(found->bypass == NULL){
        curAction->lastDefList.push_back(found);
      } else {
        // If we have a POP as the last def and its a save-restore reg (i.e. found->bypass is a thing)
        // then reroute last def. Only way a pop can be last def is for a given register
        curAction->lastDefList.push_back(found->bypass);
      }
    }
  }
}

void taintRegOps(TaintState *backTaint, ReaderOp *op, Action *curAction, std::map<uint64_t, Action *> &mapLabelToAction, uint64_t actionLabel){
  // Get parent reg from op->reg
  LynxReg parent = LynxReg2FullLynxReg(op->reg);
  //printf("REGGGGG:%s=", LynxReg2Str(parent));
  taintReg(backTaint,(LynxReg) parent, curAction->tid, actionLabel);
  //printf("Adding label %ld  to map to action %lx, Tainting reg op\n", actionLabel, curAction->instruction->event.ins.addr);
}

void taintMemOps(TaintState *backTaint, ReaderOp *op, Action *curAction, std::map<uint64_t, Action *> &mapLabelToAction, uint64_t actionLabel){
  if(op->type != MEM_OP){
    return;
  }
  taintMem(backTaint, op->mem.addr, op->mem.size, actionLabel);
  //printf("Adding label %ld  to map to action %lx, Tainting mem op\n", actionLabel, curAction->instruction->event.ins.addr);
}

void taintRegMemOps(TaintState *backTaint, ReaderOp *op, Action *curAction, std::map<uint64_t, Action *> &mapLabelToAction, uint64_t actionLabel){
  if(op->type == REG_OP){
    taintRegOps(backTaint, op, curAction, mapLabelToAction, actionLabel);
  } else if(op->type == MEM_OP){
    taintMemOps(backTaint, op, curAction, mapLabelToAction, actionLabel);
  }
}

uint8_t canSkipTaintBecauseInsType(xed_iclass_enum_t inst){
  uint8_t isRet = (inst == XED_ICLASS_RET_FAR || inst == XED_ICLASS_RET_NEAR || inst == XED_ICLASS_IRET || inst == XED_ICLASS_IRETD || inst == XED_ICLASS_IRETQ || inst == XED_ICLASS_SYSRET || inst == XED_ICLASS_SYSRET_AMD);
  uint8_t isCall = (inst == XED_ICLASS_CALL_FAR || inst == XED_ICLASS_CALL_NEAR || inst == XED_ICLASS_SYSCALL || inst == XED_ICLASS_SYSCALL_AMD);
  uint8_t isLeave = (inst == XED_ICLASS_LEAVE);
  uint8_t isEnter = (inst == XED_ICLASS_ENTER);
  uint8_t isRIPUser = (isConditionalJump(inst) || isUnconditionalJump(inst));
  return(isRet || isCall || isLeave || isEnter || isPushIns(inst) || isPopIns(inst) || isRIPUser);
}

void taintDests(TaintState *backTaint, Action *curAction, std::map<uint64_t, Action *> &mapLabelToAction, uint8_t keepReg){

  // Get a new label to apply to all dest/sources
  uint64_t actionLabel = getNewLabel(backTaint);
  mapLabelToAction[actionLabel] = curAction;
  InsInfo *info = curAction->curInfo;

  // Walk through source ops
  ReaderOp *op = info->srcOps;

  // Now go through read/write ops
  op = info->readWriteOps;
  for(int i = 0; i < info->readWriteOpCnt; i++){
    // If we have a ret/call/leave/enter/ect that reads taint from RSP/RIP, then ignore it (keepReg flag)
    xed_iclass_enum_t inst = info->insClass;
    if(!keepReg && canSkipTaintBecauseInsType(inst)){
      if(op->type == REG_OP){
        LynxReg parent = LynxReg2FullLynxReg(op->reg);
        if(parent == LYNX_RSP || parent == LYNX_RIP || (parent == LYNX_RBP && (inst == XED_ICLASS_LEAVE || inst == XED_ICLASS_ENTER))){
          //printf("We have a %s ins writing to %s\n", xed_iclass_enum_t2str(inst), LynxReg2Str(parent));
          op = op->next; // HANDLE: RSP cases
          continue;
        }
      }
    }
    taintRegMemOps(backTaint, op, curAction, mapLabelToAction, actionLabel);
    op = op->next;
  }

  // Finally dstOps
  op = info->dstOps;
  for(int i = 0; i < info->dstOpCnt; i++){
    // If we have a ret/call/leave/enter/ect that reads taint from RSP/RIP, then ignore it (keepReg flag)
    xed_iclass_enum_t inst = info->insClass;
    if(!keepReg && canSkipTaintBecauseInsType(inst)){
      if(op->type == REG_OP){
        LynxReg parent = LynxReg2FullLynxReg(op->reg);
        if(parent == LYNX_RSP || parent == LYNX_RIP || (parent == LYNX_RBP && (inst == XED_ICLASS_LEAVE || inst == XED_ICLASS_ENTER))){
          //printf("We have a %s ins writing to %s\n", xed_iclass_enum_t2str(inst), LynxReg2Str(parent));
          op = op->next;
          continue;
        }
      }
    }
    taintRegMemOps(backTaint, op, curAction, mapLabelToAction, actionLabel);
    op = op->next;
  }
}

void handlePush(Action *curAction, map<uint32_t, map<LynxReg, Action *>> &mapTIDToPushMap){
  mapTIDToPushMap[curAction->tid][curAction->reg] = curAction;
  //printf("PUSH: PUSH writing to %s:%d\n", LynxReg2Str(curAction->reg), curAction->instruction->event.ins.tid); 
}

int handlePop(Action *curAction, map<uint32_t, map<LynxReg, Action *>> &mapTIDToPushMap){
  if(mapTIDToPushMap[curAction->tid].find(curAction->reg) == mapTIDToPushMap[curAction->tid].end()){
    //printf("POP: No push to REG %s:%d\n", LynxReg2Str(curAction->reg), curAction->instruction->event.ins.tid);
    return 0;
  }
  Action *push = mapTIDToPushMap[curAction->tid][curAction->reg];
  if(push->rspVal == curAction->rspVal && push->reg == curAction->reg){
    const uint8_t *pushVal = push->regVal;
    const uint8_t *popVal = curAction->regVal;
    int sizePush = LynxRegSize(push->reg);
    int sizePop = LynxRegSize(curAction->reg);
    if(pushVal == NULL || popVal == NULL){
      return 0;
    }
    if(sizePush != sizePop){
      return 0;
    }
    for(int walk = 0; walk < sizePush; walk++){
      if(pushVal[walk] != popVal[walk]){
        return 0;
      }
    }
    //printf("POP: POP matching with push %s\n", LynxReg2Str(curAction->reg));
    return 1;
  }
  return 0;
}

void findAllLastDefinitions(SliceState *slice, Action *action, uint8_t keepReg){
  // Get our taint state
  TaintState *backTaint = slice->taintState;
  // We will need a mapping of labels to actions
  std::map<uint64_t, Action *> mapLabelToAction;
  std::map<uint32_t, map<LynxReg, Action *>> mapTIDToPushMap;
 // printf("Walking through all actions at positions n - 0 ending at position %ld \n", action->position);
  // Walk backwards through trace from slice starting position
  // Find all last definitions along the way for every action
  uint64_t position = action->position;
  uint64_t walk = 0;
  //printf("Starting\n");
  while(walk <= position){
    // Grab our action
    action = getActionAtIndex(slice, walk);
   // printf("Current action is %lx at %ld\n", getAddrFromAction(action), walk);
    if(action->instruction->event.type != EXCEPTION_EVENT){
      if(!keepReg && isPushIns(action->curInfo->insClass)){
        handlePush(action, mapTIDToPushMap);
      }
      // Add current action to all appropriate last def lists
      collectLastDefinitionsUsingCurAction(backTaint, action, mapLabelToAction, keepReg);
      // Taint destinations, any instructions that end up having these as sources trace back the taint to this ins
      uint8_t haveSaveRestorePair = 0;
      if(!keepReg && isPopIns(action->curInfo->insClass)){
        haveSaveRestorePair = handlePop(action, mapTIDToPushMap);
        // If we have a save restore pair then set up the bypass in last defs
        if(haveSaveRestorePair){
          action->bypass = mapTIDToPushMap[action->tid][action->reg]->lastDefForRegOnPush;
        }
      }
      taintDests(backTaint, action, mapLabelToAction, keepReg);
      //outputTaint(backTaint);
      //printf("\n\n");
    }
    // And move to next action
    walk++;
  }
}

void markAction(SliceState *slice, Action *action){
  slice->numMarked++;
  action->marked = 1;
  slice->marked.insert(action);
}

void visitAction(SliceState *slice, Action *action){
  slice->numVisited++;
  action->visited = 1;
  slice->visited.insert(action);
}

void markRemainingActions(SliceState *slice, uint64_t posi, set<Action *> contributing, set<Action *> noncontributing){
  uint64_t i;
  for(i = 0; i < posi; i++){
    if(contributing.find(getActionAtIndex(slice, i)) == contributing.end() && noncontributing.find(getActionAtIndex(slice, i)) == noncontributing.end()){
      markAction(slice, getActionAtIndex(slice, i));
    }
  }
}

void findContributing(SliceState *slice, set<Action *> &markedAndNotVisited){
  while(!markedAndNotVisited.empty()){
    // Get a marked + nonvisited action from the set
    Action *current = *markedAndNotVisited.begin();
    //printf("Got %lx from marked set\n", getAddrFromAction(current));
    // Visit it
    slice->visited.insert(current);
    // Add into set of contributing actions
    slice->contributing.insert(current);
    // Go through and mark all actions in lastDef list
    for(Action *lastDef : current->lastDefList){
      //printf("    Considering %lx from last def list of %lx position %ld\n", getAddrFromAction(lastDef), getAddrFromAction(current), current->position);
      markAction(slice, lastDef);
      // Optimization to add into markedAndNotVisited WITHOUT a set_diff
      // If this action is not yet visited, add into markedAndNotVisited set
      if(slice->visited.find(lastDef) == slice->visited.end()){
        markedAndNotVisited.insert(lastDef);
        //printf("    Marking %lx from last def list of %lx\n", getAddrFromAction(lastDef), getAddrFromAction(current));
      } else {
        slice->contributing.insert(lastDef);
      }
    }
    // For all blocks, see if action is a part-of the block and remove block from set if so
    //blockSlice *block = getBlockSlice(slice, getActionAtIndex(slice, current->position));
    blockSlice *block = current->bbl;
    //printf("      Saving block %ld from remove set due to residence of action %lx as a last def\n", block->id, getAddrFromAction(current));
    slice->removableBlocks.erase(block);

    // At this point current has been visited
    markedAndNotVisited.erase(current);
    //printf("%ld is size of markedAndNotVisited set\n", markedAndNotVisited.size());
    //printf("%ld is size of marked set\n", slice->marked.size());
  }
 // printf("%ld is size of marked set\n", slice->marked.size());
 // printf("One iteration of find contributing has finished\n");
}

bool isREntry(SliceState *slice, Action *action){
  // Check if previous action was a jump
  if(action->position >= 1){
    xed_iclass_enum_t prevIns = getActionAtIndex(slice, action->position-1)->curInfo->insClass;
    if((isConditionalJump(prevIns) && !(StraightLineCode(getActionAtIndex(slice, action->position-1)->instruction->event.ins, action->instruction->event.ins))) || isUnconditionalJump(prevIns)){
      return(false);
    }
  }
  // Now see if this action is at a start of a block
  // NOTE: We are using the cfg instruction as many actions can map to one cfgInstruction
  // Actions can be duplicated, cfgInstructions are not
  if(getActionAtIndex(slice, action->bbl->start)->instruction == action->instruction){
    return(true);
  }
  return(false);
}

bool isRExit(SliceState *slice, Action *exitAction){
  uint64_t position = exitAction->position;
  Action *endOfBlock = getActionAtIndex(slice, exitAction->bbl->end);
  if(exitAction->instruction != endOfBlock->instruction){
    return false;
  }
  if(isUnconditionalJump(exitAction->curInfo->insClass)){
    return false;
  } else if(isConditionalJump(exitAction->curInfo->insClass) && (position+1 < slice->numActions) &&\
            !(StraightLineCode(exitAction->instruction->event.ins, (getActionAtIndex(slice, position+1)->instruction->event.ins)))){
    return false;
  }
  return true;
}

// RExit is instruction immediately after a block ends,
// where the previous action is not a jump
Action *findNearestRExit(SliceState *slice, Action *from, uint64_t stop){
  //printf("  Scanning for rexit between %ld and %ld\n", from->position, stop);
  uint64_t position = from->position;
  Action *nearestRExitAct = NULL;
  // Search for exit
  Action *exitActionTest = NULL;
  position++;
  while(position < stop){
    exitActionTest = getActionAtIndex(slice, position);
    // Check if its a jump exit
    //printf("    Scanning: Observing action at pos %ld: is rexit: \n", position);
    if(isRExit(slice, exitActionTest)){
      nearestRExitAct = exitActionTest;
      //printf("    Scanning: next r-exit found at %ld\n", nearestRExitAct->position);
    }
    position++;
  }
  if(nearestRExitAct == NULL){
    return NULL;
  }
  // Otherwise return instruction that immediately follows
  return getActionAtIndex(slice, nearestRExitAct->position+1);
}

set<Action *> findNonContributing(SliceState *slice, uint64_t sliceSpot){
  set<Action *> nonContributing;
  uint64_t posi = 0;
  while (posi < sliceSpot){
    Action *current = getActionAtIndex(slice, posi);
    // If our action isn't in the contributing set and is at an RENTRY
    if(slice->contributing.find(current) == slice->contributing.end() && isREntry(slice, current)){
      //printf("%lx is being considered for non contributing\n", getAddrFromAction(current));
      // Find nearest contributing action
      uint64_t nearestContribPos = posi+1;
      while(slice->contributing.find(getActionAtIndex(slice, nearestContribPos)) == slice->contributing.end()){
        nearestContribPos++;
      }
      // If there is a nearest contributing action
      if(nearestContribPos > posi && nearestContribPos <= sliceSpot){
        // Grab it. The position it resides at is walk
        Action *contributingNearest = getActionAtIndex(slice, nearestContribPos);
        //printf("  %lx  at position %ld has found a nearest contributing action %lx\n", getAddrFromAction(current), posi, getAddrFromAction(contributingNearest));
        // We know that current is at an R entry (see above)
        // Try to find nearest r-exit between our selected r-entry and the contributing action
        Action *rexit = findNearestRExit(slice, current, nearestContribPos);
        // If we found a nearest r-exit and if its position is before t
        set<Action *> temp;
        uint64_t nonContribWalk = posi;
        // Now check if there is a closest rexit of current->bbl before our contributing action
        if(rexit != NULL && rexit->position <= contributingNearest->position){
          //printf("  %lx has found an r-exit %lx before the contributing action %lx\n", getAddrFromAction(current), getAddrFromAction(rexit), getAddrFromAction(contributingNearest));
          // Add Instructions to temp set
          while(nonContribWalk < rexit->position){ // grabz
            nonContributing.insert(getActionAtIndex(slice, nonContribWalk));
            nonContribWalk++;
          }
          posi = nonContribWalk - 1;
        }
      }
    }
    posi++;
  }
  return(nonContributing);
}

void printLastDefs(SliceState *slice, uint64_t numActions){
  for(uint64_t i = 0; i < numActions; i++){
    Action *temp = getActionAtIndex(slice, i);
    if(!temp->lastDefList.empty()){
      printf("Last definitions of %lx are: ", getAddrFromAction(temp));
      for(Action *temps : temp->lastDefList){
        printf("%lx in phase %d ", getAddrFromAction(temps), temps->instruction->block->fun->cfgPhase->id);
      }
      printf("\n");
    }
  }
}


/*******************************************************************************
 *                                                                             *
 * build_action_list() -- construct a list (array) of actions corresponding to *
 * the trace.  This list is traversed when computing the slice.                *
 *                                                                             *
 *******************************************************************************/

void build_action_list(SlicedriverState *driver_state) {
  Action **listOfActions = (Action **) malloc(driver_state->numIns * sizeof(Action *));
  uint64_t position = 0;

  driver_state->slice_start_action = NULL;
  driver_state->num_actions = 0;
  driver_state->listOfActions = listOfActions;

  for (std::pair<cfgInstruction *, infoTuple *> collection : *(driver_state->insCollection)) {
    cfgInstruction *instruction = (std::get<0>(collection));
    infoTuple *savedInfo = (std::get<1>(collection));
    InsInfo *curInfo = savedInfo->storedInfo;

    Action *this_action = new Action();
    this_action->position = position;
    this_action->instruction = instruction;
    this_action->instruction->keep = 2;
    this_action->keep = 2;
    this_action->curInfo = curInfo;
    this_action->bbl = NULL;
    this_action->bypass = NULL;
    this_action->tid = savedInfo->tid;
      
    // Handle push/pops
    xed_iclass_enum_t inst = curInfo->insClass;
    if (!driver_state->keepReg
	&& instruction->event.type != EXCEPTION_EVENT
	&& (isPopIns(inst) || isPushIns(inst))) {
      this_action->regVal = savedInfo->regVal;
      this_action->rspVal = savedInfo->rspVal;
      this_action->reg = savedInfo->reg;
    }
    
    listOfActions[position] = this_action;
    position++;

    if (instruction->event.type == INS_EVENT
	&& instruction->event.ins.addr == driver_state->sliceAddr) {
      driver_state->slice_start_action = this_action;
      driver_state->num_actions = position;
    }
  }

  return;
}


/*******************************************************************************
 *                                                                             *
 * compute_slice() -- computes a backward dynamic slice using information in   *
 * the argument driver_state.                                                  *
 *                                                                             *
 *******************************************************************************/

SliceState *compute_slice(SlicedriverState *driver_state){
  build_action_list(driver_state);

  if (driver_state->slice_start_action == NULL) {
    fprintf(stderr, "Could not find action at address 0x%lx\n", driver_state->sliceAddr); 
    exit(1);
  }
    
  ReaderState *rState = driver_state->rState;
  TaintState *backTaint = driver_state->backTaint;
  uint64_t numActions = driver_state->num_actions;
  Action **listOfActions = driver_state->listOfActions;
  Action *startOfSlice = driver_state->slice_start_action;

  SliceState *slice = new SliceState();
  slice->listOfActions = listOfActions;
  slice->numActions = numActions;
  slice->readerState = rState;
  slice->taintState = backTaint;
  // Build blocks
  buildBlocks(slice);
  // Set all actions in Trace as unmarked/unvisited
  setAllNotMarkedOrVisited(slice);
  // Find last defitions
  //printf("Finding last defs\n");
  findAllLastDefinitions(slice, startOfSlice, driver_state->keepReg);
  // Walk through and print all last definisitons
  //printLastDefs(slice, numActions);
  // Mark the start of our slice (its not visited yet though)
  //printf("Marking\n");
  markAction(slice, startOfSlice);
  // Get our set of marked + not visited actions
  set<Action *> markedAndNotVisited;
  set<Action *> nonContributing;
  markedAndNotVisited.insert(startOfSlice);
  // And loop until there does not exist a marked and not visited action
  uint64_t iterationsOuter = 0;
  do {
    // Find contributing
    findContributing(slice, markedAndNotVisited);
    // Find non-contributing
    nonContributing = findNonContributing(slice, startOfSlice->position);
    // Mark remaining actions
    markRemainingActions(slice, startOfSlice->position, slice->contributing, nonContributing); 
    // Set subtraction of marked - visited = how many marked + nonvisited actions we have
    markedAndNotVisited.clear();
    set_difference(slice->marked.begin(), slice->marked.end(), slice->visited.begin(), slice->visited.end(), inserter(markedAndNotVisited, markedAndNotVisited.end()));
    iterationsOuter++;
  } while(!markedAndNotVisited.empty());

  // Print non contributing
  uint64_t remove = 0;
  for (blockSlice *block : slice->removableBlocks){
    for(uint64_t actPosition : block->actionsSet){
      Action *act = getActionAtIndex(slice, actPosition);
      act->keep = 0;
      remove++;
      if(act->instruction->event.type != EXCEPTION_EVENT){
        if(slice->contributing.find(act) != slice->contributing.end()){
          printf("CONFLICT %lx %s is both in contributing and removable!\n", getAddrFromAction(act), act->curInfo->mnemonic);
          exit(1);
        }
      }
    }
  }

  uint64_t save = 0;
  for(uint64_t i = 0; i < numActions; i++){
    Action *act = getActionAtIndex(slice, i);
    if(act->keep == 2){
      act->instruction->keep = 1;
      act->keep = 1;
      slice->saveableCFGInstructions.insert(act->instruction);
      save++;
      if(driver_state->validate && act->instruction->event.type != EXCEPTION_EVENT){
        printf("%ld %lx %s\n", act->position, getAddrFromAction(act), act->instruction->block->fun->name);
      }
    } else if(act->instruction->keep != 1) {
      act->instruction->keep = 0;
      slice->removableCFGInstructions.insert(act->instruction);
    }
  }
  
  printf("%ld removable actions\n", remove);
  printf("%ld contributing actions\n", save);
  printf("%ld removable cfgInstructions\n", slice->removableCFGInstructions.size());
  printf("%ld saveable cfgInstructions\n", slice->saveableCFGInstructions.size());
  printf("%ld total cfgInstructions\n", slice->saveableCFGInstructions.size() + slice->removableCFGInstructions.size());
  printf("%ld iterations of outer loop\n\n", iterationsOuter);

  print_slice_instrs(slice);
  
  return(slice);
}

