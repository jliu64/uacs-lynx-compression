/**
 * This is the driver for the trace2ascii tool. Most of the work is done by the reader. In here, we just get
 * instructions one by one and print out the information to STDOUT. It should be noted that we are currently
 * only printing out an instruction's: address, source name, function name, thread id, bytes and mnemonic.
 **/

#include <Reader.h>
#include <Taint.h>
#include <stdio.h>
#include <stdlib.h>

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
    if(argc != 2) {
        printf("%s <trace>\n", argv[0]);
        return 1;
    }


    ReaderState *readerState = initReader(argv[1], 0);
    TaintState *taintState = initTaint(readerState);

	ReaderEvent curEvent;
    uint64_t constLabel = getNewLabel(taintState);

    int i;
    for(i = 0; i < numSegments(readerState); i++) {
        const SegmentLoad *seg = getSegment(readerState, i);
        fprintf(stderr, "tainting %llx %llx\n", (unsigned long long) seg->addr, (long long) seg->size);

        taintMem(taintState, seg->addr, seg->size, constLabel);
    }

    for(i = 0; i < getNumThreads(readerState); i++) {
        int j;
        for(j = LYNX_FIRST; j <= LYNX_LAST_FULL; j++) {
            taintReg(taintState, (LynxReg) j, i, constLabel);
        }
    }




    InsInfo info;
    initInsInfo(&info);
    char first = 1;
    char printWrites = 0;

    uint32_t mainId = findString(readerState, "main");

    int run = 0;
    uint32_t syscallTid = 0;
    int checkOpenResult = 0;

    while(nextEventWithCheck(readerState, &curEvent, &info)) {
        if(curEvent.type == EXCEPTION_EVENT) {
            printf("EXCEPTION %d\n", curEvent.exception.code);
        }
        else if(curEvent.type == INS_EVENT) {
            int tainted = 0;

            if(first) {
                uint64_t rsp = *((uint64_t *) getRegisterVal(readerState, LYNX_RSP, syscallTid));
                printf("tainting %llx\n", (unsigned long long) rsp);
                taintMem(taintState, rsp, 0x70, constLabel);
                first = 0;
            }
            else {
                int i;
                if(printWrites) {
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
                    printf("\n");
                    printWrites = 0;
                }
            }
            
            fetchInsInfo(readerState, &curEvent.ins, &info);

            if(checkOpenResult && curEvent.ins.tid == syscallTid) {
                checkOpenResult = 0;
                uint64_t fd = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, syscallTid));

                fprintf(stderr, "' -- %llu\n", (unsigned long long) fd);
            }
            else if(info.insClass == XED_ICLASS_SYSCALL) {
                uint64_t callNum = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));

                //read
                if(callNum == 0) {
                    uint64_t fd = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                    uint64_t addr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                    uint64_t size = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                    tainted = 1;
                    //uint64_t dataLabel = getNewLabel(forwardTaint);

                    taintMem(taintState, addr, size, constLabel);
                    fprintf(stderr, "reading %llu %llx[%llu]\n", (unsigned long long) fd, (unsigned long long) addr, (unsigned long long) size);
                }
                //open
                else if(callNum == 2) {
                    uint64_t filename = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));

                    fprintf(stderr, "open '");
    
                    char curChar;
                    getMemoryVal(readerState, filename++, 1, (uint8_t *) &curChar);
                    while(curChar != 0) {
                        fprintf(stderr, "%c", curChar);
                        getMemoryVal(readerState, filename++, 1, (uint8_t *) &curChar);
                    }

                    syscallTid = curEvent.ins.tid;
                    checkOpenResult = 1;
                }
            }

/*            if(!run) {
                if(curEvent.ins.fnId != mainId) {
                    continue;
                }
                
                uint64_t rsp = *((uint64_t *) getRegisterVal(readerState, LYNX_RSP, 0));
                taintMem(taintState, rsp, 24, constLabel);
                
                run = 1;
            }*/




            /*if(info.insClass == XED_ICLASS_SYSCALL) {
                uint64_t rax = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));

                printf("Syscall: %lld\n", (long long) rax);

                if(rax == 0) {
                    tainted = 1;
                    uint64_t rdx = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                    uint64_t rsi = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                    fprintf(stderr, "tainting %llx %llx\n", (unsigned long long) rsi, (long long) rdx);

                    taintMem(taintState, rsi, rdx, constLabel);
                }
            }*/


            if(!tainted) {
                //if(curEvent.ins.addr == 0x7f2e539e6263 && curEvent.ins.addr == 0x7f2e53963ce4) {
                if(propagateConst(taintState, &curEvent, &info)) {
                    printf(" * ");
                }

                /*if(info.insClass == XED_ICLASS_JMP || info.insClass == XED_ICLASS_JMP_FAR || info.insClass == XED_ICLASS_CALL_FAR || info.insClass == XED_ICLASS_CALL_NEAR) {
                    printf("> %llx %llx %s\n", (unsigned long long) label, (unsigned long long) curEvent.ins.addr, info.mnemonic);
                }*/
                
            }

            printWrites = 1;

            printf("%d %llx %s %s ", curEvent.ins.tid, (unsigned long long) curEvent.ins.addr, fetchStrFromId(readerState, curEvent.ins.srcId), fetchStrFromId(readerState, curEvent.ins.fnId));

            int i;
            for(i = 0; i < curEvent.ins.binSize; i++) {
                printf("%02x ", curEvent.ins.binary[i]);
            }
            printf("%s ", info.mnemonic);
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
        else {
            printf("UNKNOWN EVENT TYPE\n");
        }
    }

    freeInsInfo(&info);
	closeReader(readerState);
    freeTaint(taintState);

	return 0;
}
