# Trace Reader API #

To use the library, you'll have to include `Reader.h`. This file contains the API and all of the necessary structs you'll need. Below there is some more information about the API.

`ReaderState *initReader(char *filename, uint32_t debug)`
* This function must be called before ANY other function in the reader. It will set up and return the state needed to read a trace.

`void closeReader(ReaderState *state)`
* This function is intended to be called after reading the trace is complete. It closes the trace file and frees the shadow architecture. 

`uint32_t nextEvent(ReaderState *state, ReaderEvent *event)`
* The nextEvent function will fetch the next event from a trace and store it in the ReaderEvent struct passed in as an arguement. It will return a 1 if an instruction was read from the trace and 0 if the end of the trace has been reached

`uint32_t nextEventWithCheck(ReaderState *state, ReaderEvent *nextEvent, InsInfo *curInfo)`
* The previous function and this function perform very similar operations. In addition to everything that nextEvent does, it also goes through checks to ensure that the shadow architecture is consistent. To do this, it requires the InsInfo of the current instruction to check against data read from the trace, so make sure you pass in a container for the next instruction, and the InsInfo from the current instruction.

`void getMemoryVal(ReaderState *state, uint64_t addr, uint32_t size, uint8_t *buf)`
* To get a region of memory from the shadow memory, use this function. One thing to watch out for is that the function expects that buf will have at least size bytes available to store the region into.

`const uint8_t *getRegisterVal(ReaderState *state, LynxReg reg, uint32_t thread)`
* Similar to getMemoryVal, this API allows you to get a register from the shadow registers.

`const char *fetchSrcName(ReaderState *state, ReaderIns *ins)`
* Fetches the source name that corresponds to the source ID stored in the ReaderIns.

`const char *fetchFnName(ReaderState *state, ReaderIns *ins)`
* Fetches the function name that corresponds to the function ID stored in the ReaderIns.

`void initInsInfo(InsInfo *info)`
* Initializes the initInsInfo struct. This needs to be done before InsInfo can be used because, despite the way it looks, the Ops are not stored in an array. They are stored in a partially statically defined linked list so that we rarely need to dynamically allocate more memory. Thus one of the big responsibilities of initInsInfo is to set up this list. One important side effect of this is you can't loop until next is null like most linked lists, so when looping over all of the ops make sure you use the corresponding count field.

`int fetchInsInfo(ReaderState *state, ReaderIns *ins, InsInfo *info)`
* Retrieves additional information about the instruction from the disassembler. This information includes the instruction's operands, textual representation and instruction type (i.e. push, pop, add, etc). Ensure that initInsInfo was called on the InsInfo struct passed into the second arguement before calling this function. Additionally 1 will be returned if an error was encountered, and 0 will otherwise be returned.

`void freeInsInfo(InsInfo *info)`
* Recovers the memory used in the InsInfo struct

`uint64_t getCurEid(ReaderState *state)`
* Returns a unique ID for the previous ReaderEvent

`uint32_t getNumThreads(ReaderState *state)`
* Returns the total number of threads used in the trace

`uint32_t loadedFromSegment(ReaderState *state, uint64_t addr)`
* Returns whether or not a particular address was loaded from the executable. 

`uint8_t hasFields(ReaderState *state, uint32_t sel)`
* Checks if the data is present in the trace (See DataSelect in `../shared/header.h`). This allows you to check if all of the data necessary for an analysis is present. Make sure you use getSelMask to get the mask of the desired state.

`ReaderOp *nextOp(ReaderOp *curOp, uint8_t totalOpCnt, uint8_t curIt)`
* This is an iterator for the ReaderOps stored in the InsInfo struct since it is often iterated over incorrectly. The data structure used to store operands is neither a struct or a linked list, but a mixture of both to reduce the amount of dynamic allocation required.

`uint8_t getMemReads(InsInfo *info, ReaderOp **readOps)`
* This will fetch all of the memory reads from the InsInfo struct. Note, you must pass in an array of ReaderOp * large enough to hold all of the memory reads. This can either be done by passing in an array of size 32 since there will never be more than 32 reads, or by allocating an array of size `(info->srcOpCnt + info->readWriteOpCnt)`. The number of memory reads filled in will be returned.

`uint8_t getMemWrites(InsInfo *info, ReaderOp **writeOps)`
* This will fetch all of the memory writes from the InsInfo struct. Note, you must pass in an array of ReaderOp * large enough to hold all of the memory writes. This can either be done by passing in an array of size 32 since there will never be more than 32 writes, or by allocating an array of size `(info->dstOpCnt + info->readWriteOpCnt)`. The number of memory writes filled in will be returned.

