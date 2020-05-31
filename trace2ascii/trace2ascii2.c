/**
 * This is the driver for the trace2ascii tool. Most of the work is done by the reader. In here, we just get
 * instructions one by one and print out the information to STDOUT. It should be noted that we are currently
 * only printing out an instruction's: address, source name, function name, thread id, bytes and mnemonic.
 **/

#include <Reader.h>
#include "stdio.h"

uint8_t hasData; 
uint8_t hasSrcId;
uint8_t hasFnId; 
uint8_t hasAddr;
uint8_t hasBin; 
uint8_t hasTid;

void printMemOp(ReaderState readerState, const char *prefix, ReaderOp *op, FILE *out) {
    fprintf(out, "%s[%llx]=", prefix, (unsigned long long) op->mem.addr);
    uint8_t *buf = malloc(sizeof(uint8_t) * op->mem.size);

    getMemoryVal(readerState, op->mem.addr, op->mem.size, buf);

    int i;
    for(i = op->mem.size - 1; i >= 0; i--) {
        fprintf(out, "%02x", buf[i]);
    }
    fprintf(out, " ");

    free(buf);
}

void printRegOp(ReaderState readerState, const char *prefix, ReaderOp *op, uint32_t tid, FILE *out) {
    fprintf(out, "%s:%s=", prefix, LynxReg2Str(op->reg));

    const uint8_t *val = getRegisterVal(readerState, op->reg, tid);

    int i;
    for(i = LynxRegSize(op->reg) - 1; i >= 0; i--) {
        fprintf(out, "%02x", val[i]);
    }

    fprintf(out, " ");
}

int doStuff(ReaderState readerState, ReaderEvent *curEvent, InsInfo *info, char *first, FILE *out) {
    if(nextEvent(readerState, curEvent)) {
        if(curEvent->type == EXCEPTION_EVENT) {
            fprintf(out, "EXCEPTION %d\n", curEvent->exception.code);
        }
        else if(curEvent->type == INS_EVENT) {
            if(*first) {
                *first = 0;
            }
            else {
                int i;
                if(hasBin) {
                    if(hasData) {
                        ReaderOp *curOp = info->readWriteOps;
                        for(i = 0; i < info->readWriteOpCnt; i++) {
                            if(curOp->type == MEM_OP) {
                                printMemOp(readerState, "MW", curOp, out);
                            }
                            else if(curOp->type == REG_OP) {
                                printRegOp(readerState, "W", curOp, curEvent->ins.tid, out);
                            }
                            curOp = curOp->next;
                        }

                        curOp = info->dstOps;
                        for(i = 0; i < info->dstOpCnt; i++) {
                            if(curOp->type == MEM_OP) {
                                printMemOp(readerState, "MW", curOp, out);
                            }
                            else if(curOp->type == REG_OP) {
                                printRegOp(readerState, "W", curOp, curEvent->ins.tid, out);
                            }
                            curOp = curOp->next;
                        }
                    }
                }
                fprintf(out, "\n");
            }

            if(hasTid) {
                fprintf(out, "%d ", curEvent->ins.tid);
            }

            if(hasAddr) {
                fprintf(out, "%llx ", (unsigned long long) curEvent->ins.addr);
            }

            if(hasSrcId) {
                fprintf(out, "%s ", fetchSrcName(readerState, &curEvent->ins));
            }

            if(hasFnId) {
                fprintf(out, "%s ", fetchFnName(readerState, &curEvent->ins));
            }

            if(hasBin) {
                fetchInsInfo(readerState, &curEvent->ins, info);
                int i;
                for(i = 0; i < curEvent->ins.binSize; i++) {
                    fprintf(out, "%02x ", curEvent->ins.binary[i]);
                }
                fprintf(out, "%s ", info->mnemonic);
                if(hasData) {
                    ReaderOp *curOp = info->srcOps;
                    for(i = 0; i < info->srcOpCnt; i++) {
                        if(curOp->type == MEM_OP) {
                            printMemOp(readerState, "MR", curOp, out);
                        }
                        else if(curOp->type == REG_OP) {
                            printRegOp(readerState, "R", curOp, curEvent->ins.tid, out);
                        }
                        curOp = curOp->next;
                    }

                    curOp = info->readWriteOps;
                    for(i = 0; i < info->readWriteOpCnt; i++) {
                        if(curOp->type == MEM_OP) {
                            printMemOp(readerState, "MR", curOp, out);
                        }
                        else if(curOp->type == REG_OP) {
                            printRegOp(readerState, "R", curOp, curEvent->ins.tid, out);
                        }
                        curOp = curOp->next;
                    }
                }
            }        
        }
        else {
            fprintf(out, "UNKNOWN EVENT TYPE\n");
        }

        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
	if(argc != 5) {
		printf("Usage: %s <trace1> <out1> <trace2> <out2>\n", argv[0]);
		return 1;
	}

    ReaderState reader1State = initReader(argv[1], 0);
    ReaderState reader2State = initReader(argv[3], 0);

    FILE *out1 = fopen(argv[2], "w");
    FILE *out2 = fopen(argv[4], "w");

	ReaderEvent curEvent;

    hasData = hasFields(reader1State, SEL_DESTREG | SEL_MEMWRITE);
    hasSrcId = hasFields(reader1State, SEL_SRCID);
    hasFnId = hasFields(reader1State, SEL_FNID);
    hasAddr = hasFields(reader1State, SEL_ADDR);
    hasBin = hasFields(reader1State, SEL_BIN);
    hasTid = hasFields(reader1State, SEL_TID);

    InsInfo info1;
    InsInfo info2;
    initInsInfo(&info1);
    initInsInfo(&info2);

    char first1 = 1;
    char first2 = 1;

    uint8_t readingTrace1 = 1;
    uint8_t readingTrace2 = 1;

    while(1) {
        readingTrace1 = doStuff(reader1State, &curEvent, &info1, &first1, out1);
        readingTrace2 = doStuff(reader2State, &curEvent, &info2, &first2, out2);

        if(!readingTrace1 && !readingTrace2) {
            break;
        }
    }

    freeInsInfo(&info1);
    freeInsInfo(&info2);
	closeReader(reader1State);
    closeReader(reader2State);

	return 0;
}
