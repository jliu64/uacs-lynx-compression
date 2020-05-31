/**
 * This is the driver for the trace2ascii tool. Most of the work is done by the reader. In here, we just get
 * instructions one by one and print out the information to STDOUT. It should be noted that we are currently
 * only printing out an instruction's: address, source name, function name, thread id, bytes and mnemonic.
 **/

#include <cstdio>
#include <vector>
#include <utility>
#include <unordered_set>
#include <set>

using namespace std;

extern "C" {
#include <Reader.h>
#include <Taint.h>
}

char *trace = NULL;
char *beginFn  = NULL;
uint32_t beginId = -1;
char *endFn = NULL;
uint32_t endId = -1;
char *traceFn = NULL;
uint32_t traceId = -1;
int64_t targetTid = -1;
uint64_t taintAddr = 0;
unordered_set<uint64_t> disappeared;
vector<char *> interpSrc;

void printUsage(char *program) {
    printf("Usage: %s -[beft] <trace>\n", program);
    printf(" b - begin the trace at a given function\n");
    printf(" e - end the trace at a given function\n");
    printf(" f - trace only the given function\n");
    printf(" t - trace only the given thread\n");
    printf(" h - print usage\n");
}

void parseCommandLine(int argc, char *argv[]) {
    int i;
    for(i = 1; i < argc; i++) {
        if(argv[i][0] == '-' && strlen(argv[i]) == 2) {
            switch(argv[i][1]) {
                case 'b':
                    i++;
                    beginFn = argv[i];
                    break;
                case 'e':
                    i++;
                    endFn = argv[i];
                    break;
                case 'f':
                    i++;
                    traceFn = argv[i];
                    break;
                case 't':
                    i++;
                    targetTid = strtoul(argv[i], NULL, 10);
                    break;
                case 'a':
                    i++;
                    taintAddr = strtoul(argv[i], NULL, 16);
                    break;
                case 'h':
                    printUsage(argv[0]);
                    break;
                case 's':
                    i++;
                    interpSrc.push_back(argv[i]);
                    break;
                default:
                    printf("Unknown Command Line Argument %s\n", argv[i]);
                    break;
            }
        }
        else {
            trace = argv[i];
        }
    }

    return;
}

void printRegOp(ReaderState *readerState, const char *prefix, LynxReg reg, uint32_t tid) {
    reg = LynxReg2FullLynxIA32EReg(reg);
    printf("%s:%s=", prefix, LynxReg2Str(reg));

    const uint8_t *val = getRegisterVal(readerState, reg, tid);

    int i;
    for(i = LynxRegSize(reg) - 1; i >= 0; i--) {
        printf("%02x", val[i]);
    }

    printf(" ");
}

void printMemOp(ReaderState *readerState, const char *prefix, ReaderOp *op, uint32_t tid) {
    if(!op->mem.addrGen) {
        printf("%s[%llx]=", prefix, (unsigned long long) op->mem.addr);
        uint8_t *buf = new uint8_t[op->mem.size];

        getMemoryVal(readerState, op->mem.addr, op->mem.size, buf);

        int i;
        for(i = op->mem.size - 1; i >= 0; i--) {
            printf("%02x", buf[i]);
        }
        printf(" ");

        delete buf;
    }

    if(op->mem.seg != LYNX_INVALID) {
        printRegOp(readerState, "R", (LynxReg) op->mem.seg, tid);
    }
    if(op->mem.base != LYNX_INVALID) {
        printRegOp(readerState, "R", (LynxReg) op->mem.base, tid);
    }
    if(op->mem.index != LYNX_INVALID) {
        printRegOp(readerState, "R", (LynxReg) op->mem.index, tid);
    }
}


int main(int argc, char *argv[]) {
    if(argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    parseCommandLine(argc, argv);

    ReaderState *readerState = initReader(trace, 0);
    TaintState *taintState = initTaint(readerState);

	ReaderEvent curEvent;

    uint8_t hasSrcReg = hasFields(readerState, getSelMask(SEL_SRCREG));
    uint8_t hasMemRead = hasFields(readerState, getSelMask(SEL_MEMREAD));
    uint8_t hasData = hasFields(readerState, getSelMask(SEL_DESTREG)) || hasFields(readerState, getSelMask(SEL_MEMWRITE)) || hasSrcReg || hasMemRead;
    //uint8_t canDebug = hasSrcReg && hasMemRead;
    uint8_t hasSrcId = hasFields(readerState, getSelMask(SEL_SRCID));
    uint8_t hasFnId = hasFields(readerState, getSelMask(SEL_FNID));
    uint8_t hasAddr = hasFields(readerState, getSelMask(SEL_ADDR));
    uint8_t hasBin = hasFields(readerState, getSelMask(SEL_BIN));
    uint8_t hasTid = hasFields(readerState, getSelMask(SEL_TID));

    char first = 1;

    if(beginFn) {
        beginId = findString(readerState, beginFn);
        if(beginId == -1) {
            beginFn = NULL;
        }
    }

    if(endFn) {
        endId = findString(readerState, endFn);
        if(endId == -1) {
            endFn = NULL;
        }
    }

    if(traceFn) {
        traceId = findString(readerState, traceFn);
        if(traceId == -1) {
            traceFn = NULL;
        }
    }

    set<uint32_t> interpIds;
    bool found = false;
    while(!interpSrc.empty()) {
        char *src = interpSrc.back();
        interpSrc.pop_back();
        uint32_t id = findString(readerState, src);
        
        if(id != -1) {
            found = true;
            interpIds.insert(id);
        }
    }

    if(!found) {
        printf("Could not find given interpreter source\n");
        exit(1);
    }

    uint8_t foundBeginFn = (beginFn == NULL);
    uint8_t foundTraceFn = (traceFn == NULL);
    uint8_t run = foundBeginFn && foundTraceFn;
    uint8_t addrSize = getAddrSize(readerState);
    uint64_t endStackPtr = 0;
    uint32_t endStackTid = -1;

    int printWrites = 0;

    vector< pair<pair<uint64_t, uint64_t>, InsInfo *> > ops;

    //vector<pair<uint64_t, uint32_t>> memRead;

    //uint64_t dataLabel = getNewLabel(taintState);
    vector<uint64_t> jmps;
    int start = 0;
    

    uint64_t unusedLabels = 0;
    uint64_t curIns = 0;
    while(nextEvent(readerState, &curEvent)) {
        curIns++;
        if(curEvent.type == EXCEPTION_EVENT) {
            printf("EXCEPTION %d\n", curEvent.exception.code);
        }
        else if(curEvent.type == INS_EVENT) {

            if(targetTid != -1 && curEvent.ins.tid != targetTid) {
                continue;
            }

            if(!run) {
                if(!foundBeginFn) {
                    if(curEvent.ins.fnId == beginId) {
                        foundBeginFn = 1;
                        run = foundBeginFn && foundTraceFn;
                    }
                }
                if(!foundTraceFn) {
                    if(curEvent.ins.fnId == traceId) { 
                        foundTraceFn = 1;
                        endStackTid = curEvent.ins.tid;
                        endStackPtr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSP, endStackTid));
                        run = foundBeginFn && foundTraceFn;
                    }
                }

                if(!run) {
                    continue;
                }
            }

            if(endStackTid == curEvent.ins.tid) {
                uint64_t stackPtr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSP, endStackTid));
                if(stackPtr > endStackPtr) {
                    break;
                }
            }
            if(curEvent.ins.fnId == endId) {
                break;
            }


/*            InsInfo *info = new InsInfo;
            initInsInfo(info);
            fetchInsInfo(readerState, &curEvent.ins, info);

            if(!foundRead) {
                if(info->insClass == XED_ICLASS_SYSCALL) {
                    uint64_t rax = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));
                    if(rax == 0) {
                        foundRead = 1;
                    }
                }

                if(!foundRead) {
                    freeInsInfo(info);
                    free(info);
                    continue;
                }
            }

            ops.push_back(make_pair(make_pair(curIns, curEvent.ins.addr), info));*/

            if(curEvent.ins.addr == 0x7ff78db2f263) {
                start = 1;
            //if(curEvent.ins.addr == 0x523cb5) {
                unusedLabels = mergeLabels(taintState, getNewLabel(taintState), unusedLabels);
                jmps.push_back(curIns);
            }

            if(!start) {
                continue;
            }

            InsInfo *info = new InsInfo;
            initInsInfo(info);
            fetchInsInfo(readerState, &curEvent.ins, info);
            ops.push_back(make_pair(make_pair(curIns, curEvent.ins.addr), info));

/** forward taint to find dispatch

            if(info->insClass == XED_ICLASS_SYSCALL) {
                uint64_t rax = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));

                if(rax == 0) {
                    uint64_t rdx = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                    uint64_t rsi = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                    //fprintf(stderr, "tainting %llx %d\n", (unsigned long long) rsi, rdx);

                    taintMem(taintState, rsi, rdx, dataLabel);

                    //free(taint);
                }   
            }   
            
            if(propagateForward(taintState, &curEvent, info)) {
                if((info->insClass == XED_ICLASS_JMP || info->insClass == XED_ICLASS_JMP_FAR || info->insClass == XED_ICLASS_CALL_FAR || info->insClass == XED_ICLASS_CALL_NEAR) && interpIds.find(curEvent.ins.srcId) != interpIds.end()) {
                    ReaderOp *ops = info->srcOps;
                    int i;
                    for(i = 0; i < info->srcOpCnt; i++) {
                        if((ops->type == REG_OP && ops->reg != LYNX_RIP) || ops->type == MEM_OP) {
                            jmps.push_back(curIns);
                            break;
                        }
                        ops = ops->next;
                    }
                }
            }*/

            /*if(info.insClass == XED_ICLASS_SYSCALL) {
                uint64_t rax = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));

                if(rax == 0) {
                    uint64_t rdx = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                    uint64_t rsi = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                    //uint64_t *taint = malloc(sizeof(uint64_t) * rdx);
                    //memread.push_back(make_pair(rsi, rdx));
                }
            }*/
        }
    }

    uint64_t validLabels = 0;
    uint64_t uniqueId = 0;

    uint64_t maxLabel = unusedLabels;

    while(!ops.empty()) {
        pair<pair<uint64_t, uint64_t>, InsInfo *> &pair = ops.back();
        uint64_t curIns = pair.first.first;
        uint64_t addr = pair.first.second;
        InsInfo *info = pair.second;
        ops.pop_back();

        /*if(curIns % 1000000 == 0) {
            uint8_t *alive = getLabelArray(taintState);
            for(int i = 0; i < maxLabel; i++) {
                alive[i] = 1;
            }
            recoverSpace(taintState, alive);
            delete[] alive;
        }*/

        //if(addr == 0x7ff78db2f263) {
        //if(info->insClass == XED_ICLASS_JMP || info->insClass == XED_ICLASS_JMP_FAR || info->insClass == XED_ICLASS_CALL_FAR || info->insClass == XED_ICLASS_CALL_NEAR) {

        if(!jmps.empty() && curIns == jmps.back()) {
            jmps.pop_back();
            ReaderOp *ops = info->srcOps;
            int i;
            for(i = 0; i < info->srcOpCnt; i++) {
                if((ops->type == REG_OP && ops->reg != LYNX_RIP) || ops->type == MEM_OP) {
                    // uint64_t label = getNewLabel(taintState);
                    uint64_t label = popLabel(taintState, &unusedLabels);
                    addTaintToOperandList(taintState, info->srcOps, info->srcOpCnt, 0, label);
                    addTaintToOperandList(taintState, info->readWriteOps, info->readWriteOpCnt, 0, label);

                    int i;
                    ReaderOp *ops = info->dstOps;
                    for(i = 0; i < info->dstOpCnt; i++) {
                        if(ops->type == MEM_OP) {
                            if(ops->mem.seg != LYNX_INVALID) {
                                addTaintToReg(taintState, (LynxReg) ops->mem.seg, 0, label);
                            }   
                            if(ops->mem.base != LYNX_INVALID && ops->mem.base != LYNX_RIP && ops->mem.base != LYNX_RSP) {
                                addTaintToReg(taintState, (LynxReg) ops->mem.base, 0, label);
                            }   
                            if(ops->mem.index != LYNX_INVALID && ops->mem.index != LYNX_RIP && ops->mem.index != LYNX_RSP) {
                                addTaintToReg(taintState, (LynxReg) ops->mem.index, 0, label);
                            }       
                        }       
                    } 
                    printf(" > %llu %llx %llx %s\n", (unsigned long long) curIns, (unsigned long long) label, (unsigned long long) addr, info->mnemonic);
                    break;
                }
                ops = ops->next;
            }
        }
        else {
            uint64_t taint = propagateBackward(taintState, 0, info);
            if(taint) {
                //printf("%llx %s\n", (unsigned long long) addr, info->mnemonic);

/*                int propagated = 1;

                if(propagated) {
                    ReaderOp *ops = info->srcOps;
                    for(int i = 0; i < info->srcOpCnt; i++) {
                        if(ops->type == MEM_OP) {
                            if(ops->mem.base == LYNX_RIP) {
                                propagated = 0;
                                break;
                            }
                        }
                        ops = ops->next;
                    }
                }
                if(propagated) {
                    ReaderOp *ops = info->readWriteOps;
                    for(int i = 0; i < info->readWriteOpCnt; i++) {
                        if(ops->type == MEM_OP) {
                            if(ops->type == MEM_OP) {
                                if(ops->mem.base == LYNX_RIP) {
                                    propagated = 0;
                                    break;
                                }
                            }
                        }
                        ops = ops->next;
                    }
                }

                if(!propagated) {
                    disappeared.insert(taint);
                }*/

                /*int propagated = 0;
                if(info->srcFlags != 0) {
                    propagated = 1;
                }

                if(!propagated) {
                    ReaderOp *ops = info->srcOps;
                    for(int i = 0; i < info->srcOpCnt; i++) {
                        if(ops->type == REG_OP && ops->reg != LYNX_RIP && ops->reg != LYNX_RSP && ops->reg != LYNX_GFLAGS) {
                            propagated = 1;
                            break;
                        }
                        if(ops->type == MEM_OP) {
                            if(!ops->mem.addrGen) {
                                propagated = 1;
                                break;
                            }
                            if(ops->mem.seg != LYNX_INVALID && ops->mem.seg != LYNX_RSP && ops->mem.seg != LYNX_RIP) {
                                propagated = 1;
                                break;
                            }
                            if(ops->mem.index != LYNX_INVALID && ops->mem.index != LYNX_RSP && ops->mem.index != LYNX_RIP) {
                                propagated = 1;
                                break;
                            }
                            if(ops->mem.base != LYNX_INVALID && ops->mem.base != LYNX_RSP && ops->mem.base != LYNX_RIP) {
                                propagated = 1;
                                break;
                            }
                        }
                        ops = ops->next;
                    }
                }
                if(!propagated) {
                    ReaderOp *ops = info->readWriteOps;
                    for(int i = 0; i < info->readWriteOpCnt; i++) {
                        if(ops->type == REG_OP && ops->reg != LYNX_RIP && ops->reg != LYNX_RSP && ops->reg != LYNX_GFLAGS) {
                            propagated = 1;
                            break;
                        }
                        if(ops->type == MEM_OP) {
                            if(!ops->mem.addrGen) {
                                propagated = 1;
                                break;
                            }
                            if(ops->mem.seg != LYNX_INVALID && ops->mem.seg != LYNX_RSP && ops->mem.seg != LYNX_RIP) {
                                propagated = 1;
                                break;
                            }
                            if(ops->mem.index != LYNX_INVALID && ops->mem.index != LYNX_RSP && ops->mem.index != LYNX_RIP) {
                                propagated = 1;
                                break;
                            }
                            if(ops->mem.base != LYNX_INVALID && ops->mem.base != LYNX_RSP && ops->mem.base != LYNX_RIP) {
                                propagated = 1;
                                break;
                            }
                        }
                        ops = ops->next;
                    }
                }
                if(!propagated) {
                    ReaderOp *ops = info->dstOps;
                    for(int i = 0; i < info->dstOpCnt; i++) {
                        if(ops->type == MEM_OP) {
                            if(ops->mem.seg != LYNX_INVALID && ops->mem.seg != LYNX_RSP && ops->mem.seg != LYNX_RIP) {
                                propagated = 1;
                                break;
                            }
                            if(ops->mem.index != LYNX_INVALID && ops->mem.index != LYNX_RSP && ops->mem.index != LYNX_RIP) {
                                propagated = 1;
                                break;
                            }
                            if(ops->mem.base != LYNX_INVALID && ops->mem.base != LYNX_RSP && ops->mem.base != LYNX_RIP) {
                                propagated = 1;
                                break;
                            }
                        }
                        ops = ops->next;
                    }
                }

                if(!propagated) {
                    printf("disappeared\n");
                    disappeared.insert(taint);
                }*/

                /*ReaderOp *ops = info->srcOps;
                for(int i = 0; i < info->srcOpCnt; i++) {
                    if(ops->type == MEM_OP) {
                        for(pair<uint64_t, uint32_t> &read : memReads) {
                            if(ops->mem.addr > read.addr && ops->mem.addr < (read.addr + size)) {
                                validLabels = combineLabels(validLabels, taint);
                                break;
                            }
                        }
                    }
                    ops = ops->next;
                }

                ReaderOp *ops = info->readWriteOps;
                for(int i = 0; i < info->readWriteCnt; i++) {
                    if(ops->type == MEM_OP) {
                        for(pair<uint64_t, uint32_t> &read : memReads) {
                            if(ops->mem.addr > read.addr && ops->mem.addr < (read.addr + size)) {
                                validLabels = combineLabels(validLabels, taint);
                                break;
                            }
                        }
                    }
                    ops = ops->next;
                }*/
            }
        }

        freeInsInfo(info);
        delete info;
    } 


    uint8_t *labels = getLabelArray(taintState);
    uint64_t size = getNewLabel(taintState);

    /*for(auto it = disappeared.begin(); it != disappeared.end(); it++) {
        labels[*it] = 1;
    }*/

    getArchLabels(taintState, labels);
    set<uint64_t> newLabels;

    for(uint64_t i = 1; i < size; i++) {
        if(labels[i]) {
            uint64_t label = i;
            uint64_t min;
            for(min = 1; min < maxLabel; min++) {
                if(labelIsSubsetOf(taintState, min, label)) {
                    break;
                }
            }

            newLabels.insert(mergeLabels(taintState, min - 1, label));
        }
    }

    delete[] labels;
    labels = getLabelArray(taintState);

    for(auto it = newLabels.begin(); it != newLabels.end(); it++) {
        labels[*it] = 1;
    }

    outputCondensedLabels(taintState, labels);

    //getCondensedLabels(taintState);
    //outputTaint(taintState);

    freeTaint(taintState);
	closeReader(readerState);

	return 0;
}
