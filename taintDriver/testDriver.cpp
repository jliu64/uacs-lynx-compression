/**
 * This is the driver for the trace2ascii tool. Most of the work is done by the reader. In here, we just get
 * instructions one by one and print out the information to STDOUT. It should be noted that we are currently
 * only printing out an instruction's: address, source name, function name, thread id, bytes and mnemonic.
 **/

#include <cstdio>
#include <cstdlib>
#include <set>
#include <string>
#include <cstring>

using namespace std;

extern "C" {
    #include <Reader.h>
    #include <Taint.h>
    #include <sys/stat.h>
}

bool fileIsConst(string &name) {
    int len = name.length();
    return strncmp(name.data() + len - 3, ".so", 3) == 0 || strncmp(name.data() + len - 3, ".py", 3) == 0 || strncmp(name.data() + len - 4, ".pyc", 4) == 0 || strncmp(name.data() + len - 4, ".pth", 4) == 0;
}

string getNameFromMem(ReaderState *readerState, uint64_t filenameLoc) {
    string name; 
    char curChar;
    getMemoryVal(readerState, filenameLoc++, 1, (uint8_t *) &curChar);
    while(curChar != 0) {
        //fprintf(stderr, "%c", curChar);
        name += curChar;
        getMemoryVal(readerState, filenameLoc++, 1, (uint8_t *) &curChar);
    }

    return name;
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
    if(argc != 2) {
        printf("%s <trace>\n", argv[0]);
        return 1;
    }


    ReaderState *readerState = initReader(argv[1], 0);
    TaintState *taintState = initTaint(readerState);

	ReaderEvent curEvent;
    uint64_t inputLabel = getNewLabel(taintState);

    /*int i;
    for(i = 0; i < numSegments(readerState); i++) {
        const SegmentLoad *seg = getSegment(readerState, i);
        fprintf(stderr, "tainting %llx %llx\n", (unsigned long long) seg->addr, (long long) seg->size);

        taintMem(taintState, seg->addr, seg->size, inputLabel);
    }

    for(i = 0; i < getNumThreads(readerState); i++) {
        int j;
        for(j = LYNX_FIRST; j <= LYNX_LAST_FULL; j++) {
            taintReg(taintState, (LynxReg) j, i, inputLabel);
        }
    }*/




    InsInfo info;
    initInsInfo(&info);
    char first = 1;
    char printWrites = 0;

    uint32_t mainId = findString(readerState, "main");

    int run = 0;
    uint32_t syscallTid = 0;
    int checkOpenResult = 0;
    uint64_t argcLoc = 0;
    uint64_t argvLoc = 0;
    int i;

    uint64_t progArgc = 0, progArgv = 0;
    string name;
    set<uint64_t> constDescriptors;

    while(nextEventWithCheck(readerState, &curEvent, &info)) {
        if(curEvent.type == EXCEPTION_EVENT) {
            printf("EXCEPTION %d\n", curEvent.exception.code);
        }
        else if(curEvent.type == INS_EVENT) {
            uint64_t taint = 0;
            if(first) {
                uint64_t rsp = *((uint64_t *) getRegisterVal(readerState, LYNX_RSP, syscallTid));
                argcLoc = rsp;
                argvLoc = rsp+8;
                
                /*printf("tainting %llx\n", (unsigned long long) rsp);
                taintMem(taintState, rsp, 0x70, inputLabel);*/
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
            ReaderOp *reads[32];
            int size = getMemReads(&info, reads);

            if(progArgc == 0 || progArgv == 0) {
                for(i = 0; i < size; i++) {
                    if(progArgc == 0 && reads[i]->mem.addr == argcLoc) {
                        getMemoryVal(readerState, argcLoc, sizeof(int), (uint8_t *)(&progArgc));
                        //printf("argc: %d\n", progArgc);
                        if(progArgv != 0) {
                            for(i = 2; i < progArgc; i++) {
                                //printf("tainting %d\n", i);
                                taintMem(taintState, progArgv + 8 * i, 8, inputLabel);
                            }
                        }
                    }
                    if(progArgv == 0 && reads[i]->mem.addr == argvLoc) {
                        getMemoryVal(readerState, argvLoc, sizeof(char **), (uint8_t *)(&progArgv));
                        //printf("argv: %p\n", (void *)progArgv);
                        if(progArgc != 0) {
                            for(i = 2; i < progArgc; i++) {
                                //printf("tainting %d\n", i);
                                taintMem(taintState, progArgv + 8 * i, 8, inputLabel);
                            }
                        }
                    }
                }
            }

            /*if(info.insClass == XED_ICLASS_SYSCALL) {
                uint64_t callNum = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));
                printf("%llu\n", (unsigned long long) callNum);
            }*/


            if(checkOpenResult && curEvent.ins.tid == syscallTid) {
                checkOpenResult = 0;
                uint64_t fd = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, syscallTid));

                //if(strncmp(name.data() - 3, ".so", 3) == 0 || strncmp(name.data()-3, ".py", 3) == 0 || strncmp(name.data() - 4, ".pyc", 4) == 0) {
                if(fileIsConst(name)) {
                    constDescriptors.insert(fd);
                }
                else {
                    printf("tainting %s\n", name.c_str());
                    constDescriptors.erase(fd);
                }

            }
            else if(info.insClass == XED_ICLASS_SYSCALL) {
                uint64_t callNum = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));


                switch(callNum) {
                    case 0: {
                        uint64_t fd = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                        if(constDescriptors.find(fd) == constDescriptors.end()) {
                            uint64_t addr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                            uint64_t size = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                            taintMem(taintState, addr, size, inputLabel);
                            fprintf(stderr, "reading %llu %llx[%llu]\n", (unsigned long long) fd, (unsigned long long) addr, (unsigned long long) size);
                            taintReg(taintState, LYNX_RAX, curEvent.ins.tid, inputLabel);
                            taint = inputLabel;
                        }
                        break;
                    } case 3:
                    case 16:
                    case 8:
                    case 1: {
                        uint64_t fd = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                        if(constDescriptors.find(fd) == constDescriptors.end()) {
                            taintReg(taintState, LYNX_RAX, curEvent.ins.tid, inputLabel);
                            taint = inputLabel;
                        }
                        break;
                    } 
                    case 6:
                    case 4: {
                        string filename = "";
                        uint64_t nameLoc = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                        filename = getNameFromMem(readerState, nameLoc);

                        if(!fileIsConst(filename)) {
                            taintReg(taintState, LYNX_RAX, curEvent.ins.tid, inputLabel);
                            taint = inputLabel;
                        }

                        break;
                    } 
                    case 257: {
                        uint64_t filename = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));

                        //fprintf(stderr, "open '");
                        name = getNameFromMem(readerState, filename);
   
                        syscallTid = curEvent.ins.tid;
                        checkOpenResult = 1;
                        break;
                    } case 2: {
                        uint64_t filename = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));

                        //fprintf(stderr, "open '");
                        name = getNameFromMem(readerState, filename);
   
                        syscallTid = curEvent.ins.tid;
                        checkOpenResult = 1;
                        break;
                    } case 5: {
                        uint64_t fd = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                        uint64_t addr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                        if(constDescriptors.find(fd) == constDescriptors.end()) {
                            taintMem(taintState, addr, sizeof(struct stat), inputLabel);
                            fprintf(stderr, "reading %llu %llx[%llu]\n", (unsigned long long) fd, (unsigned long long) addr, (unsigned long long) size);
                            taintReg(taintState, LYNX_RAX, curEvent.ins.tid, inputLabel);
                            taint = inputLabel;
                        }
                        
                        break;
                    }
                    case 78: {
                        //uint64_t fd = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                        uint64_t addr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                        uint64_t size = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                        taintMem(taintState, addr, size, inputLabel);
                        taintReg(taintState, LYNX_RAX, curEvent.ins.tid, inputLabel);
                        taint = inputLabel;

                        
                    }
                    
                    case 89: {
                        string filename = "";
                        uint64_t nameLoc = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                        filename = getNameFromMem(readerState, nameLoc);

                        if(!fileIsConst(filename)) {
                            uint64_t addr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                            uint64_t size = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                            taintReg(taintState, LYNX_RAX, curEvent.ins.tid, inputLabel);
                            taintMem(taintState, addr, size, inputLabel);
                            taint = inputLabel;
                        }
                        break;
                    } case 13: 
                    case 9:
                    case 11:
                    case 12:
                    case 107:
                    case 108:
                    case 102:
                    case 104:
                        taintReg(taintState, LYNX_RAX, curEvent.ins.tid, inputLabel);
                        taint = inputLabel;
                        break;
                    case 79:
                        taint = inputLabel;
                        break;
                    default:
                        fprintf(stderr, "unhandled syscall: %lu\n", callNum);
                        return 1;
                    break;
                }
            }


            //continue;

            if(taint || propagateForward(taintState, &curEvent, &info)) {
                printf("T ");
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
