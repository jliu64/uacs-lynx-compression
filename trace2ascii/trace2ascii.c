/**
 * This is the driver for the trace2ascii tool. Most of the work is done by the reader. In here, we just get
 * instructions one by one and print out the information to STDOUT. It should be noted that we are currently
 * only printing out an instruction's: address, source name, function name, thread id, bytes and mnemonic.
 **/

#include <Reader.h>
#include "stdio.h"

char *trace = NULL;
char *beginFn  = NULL;
uint32_t beginId = -1;
char *endFn = NULL;
uint32_t endId = -1;
char *traceFn = NULL;
uint32_t traceId = -1;
int64_t targetTid = -1;

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
                case 'h':
                    printUsage(argv[0]);
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
        uint8_t *buf = malloc(sizeof(uint8_t) * op->mem.size);

        getMemoryVal(readerState, op->mem.addr, op->mem.size, buf);

        int i;
        for(i = op->mem.size - 1; i >= 0; i--) {
            printf("%02x", buf[i]);
        }
        printf(" ");

        free(buf);
    }

    if(op->mem.seg != LYNX_INVALID) {
        printRegOp(readerState, "R", op->mem.seg, tid);
    }
    if(op->mem.base != LYNX_INVALID) {
        printRegOp(readerState, "R", op->mem.base, tid);
    }
    if(op->mem.index != LYNX_INVALID) {
        printRegOp(readerState, "R", op->mem.index, tid);
    }
}


int main(int argc, char *argv[]) {
    if(argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    parseCommandLine(argc, argv);

    ReaderState *readerState = initReader(trace, 0);

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

    InsInfo info;
    initInsInfo(&info);
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

    uint8_t foundBeginFn = (beginFn == NULL);
    uint8_t foundTraceFn = (traceFn == NULL);
    uint8_t run = foundBeginFn && foundTraceFn;
    uint8_t addrSize = getAddrSize(readerState);
    uint64_t endStackPtr = 0;
    uint32_t endStackTid = -1;

    uint64_t n = 0;
    while(nextEvent(readerState, &curEvent)) {
        if(curEvent.type == EXCEPTION_EVENT) {
            fflush(stdout);
            printf("EXCEPTION %d at %llx\n",
		   curEvent.exception.code,
		   (unsigned long long) curEvent.exception.addr);
            fflush(stdout);
            fprintf(stderr,
		    "EXCEPTION %d at %llx\n",
		    curEvent.exception.code,
		    (unsigned long long) curEvent.exception.addr);
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

            if(first) {
                first = 0;
            }
            else {
                int i;
                if(hasBin) {
                    if(hasData) {
                        ReaderOp *curOp = info.readWriteOps;
                        for(i = 0; i < info.readWriteOpCnt; i++) {
                            if(curOp->type == MEM_OP) {
                                printMemOp(readerState, "MW", curOp, curEvent.ins.tid);
                            }
                            else if(curOp->type == REG_OP) {
                                printRegOp(readerState, "W", curOp->reg, curEvent.ins.tid);
                            }
                            curOp = curOp->next;
                        }

                        curOp = info.dstOps;
                        for(i = 0; i < info.dstOpCnt; i++) {
                            if(curOp->type == MEM_OP) {
                                printMemOp(readerState, "MW", curOp, curEvent.ins.tid);
                            }
                            else if(curOp->type == REG_OP) {
                                printRegOp(readerState, "W", curOp->reg, curEvent.ins.tid);
                            }
                            curOp = curOp->next;
                        }
                    }
                }
                printf("\n");
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

            printf("%ld:", n++);      

            if(hasTid) {
                printf(" tid=%d;", curEvent.ins.tid);
            }

            if(hasAddr) {
                printf(" 0x%llx;", (unsigned long long) curEvent.ins.addr);
            }

            if(hasSrcId) {
                printf(" %s;", fetchStrFromId(readerState, curEvent.ins.srcId));
            }

            if(hasFnId) {
                printf(" %s;", fetchStrFromId(readerState, curEvent.ins.fnId));
            }

            if(hasBin) {
                fetchInsInfo(readerState, &curEvent.ins, &info);
                int i;
                for(i = 0; i < curEvent.ins.binSize; i++) {
                    printf(" %02x", curEvent.ins.binary[i]);
                }
                printf("; %s; ", info.mnemonic);
                if(hasData) {
                    ReaderOp *curOp = info.srcOps;
                    for(i = 0; i < info.srcOpCnt; i++) {
                        if(curOp->type == MEM_OP) {
                            printMemOp(readerState, "MR", curOp, curEvent.ins.tid);
                        }
                        else if(curOp->type == REG_OP) {
                            printRegOp(readerState, "R", curOp->reg, curEvent.ins.tid);
                        }
                        curOp = curOp->next;
                    }

                    curOp = info.readWriteOps;
                    for(i = 0; i < info.readWriteOpCnt; i++) {
                        if(curOp->type == MEM_OP) {
                            printMemOp(readerState, "MR", curOp, curEvent.ins.tid);
                        }
                        else if(curOp->type == REG_OP) {
                            printRegOp(readerState, "R", curOp->reg, curEvent.ins.tid);
                        }
                        curOp = curOp->next;
                    }
                }
            }        
        }
        else {
            printf("UNKNOWN EVENT TYPE\n");
        }
    }

    freeInsInfo(&info);
	closeReader(readerState);

	return 0;
}
