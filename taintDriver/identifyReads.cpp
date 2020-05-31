#include <cstdio>
#include <vector>
#include <utility>
#include <set>
#include <cassert>
#include <unordered_map>
#include <cstring>
#include <string>

//track read size and create a new label when read size doesn't match
//every tainted write, write a new label

//taint write with generic label, taint read with  regular label
// watch size of read?

// watch for VIP?

using namespace std;

extern "C" {
    #include <Reader.h>
    #include <Taint.h>
}

char *trace = NULL;
set<uint64_t> dispatch;
vector< pair<uint64_t, uint32_t> > bytecode;
vector<char *> sources;
bool coalesce = false;

struct pairHash {
    //std::size_t operator() (const std::pair<uint64_t, uint64_t> &p) const {
    inline std::size_t operator()(const std::pair<uint64_t, uint64_t> & p) const {
        return p.first * p.second;
    }   
};

void printUsage(char *program) {
    printf("Usage: %s -t <trace> [-bd]\n", program);
    printf("  d <addr1 addr2 ...> - List of dispatch addresses\n");
    printf("  b <base1[size1] base2[size2] ...> - List identifying bytecode locations in memory\n");
    printf("* s <source1 source2 ...> - source files of interest executed by the interpereter\n");
    printf("  h - show this message\n");
    printf("  c - coalesce bytecode instructions into basic blocks\n");
    printf("* is required\n");
}

void parseCommandLine(int argc, char *argv[]) {
    int i = 1;
    while(i < argc) {
        if(argv[i][0] == '-' && strlen(argv[i]) == 2) {
            switch(argv[i][1]) {
                case 'b':
                    i++;
                    for(; i < argc && argv[i][0] != '-'; i++) {
                        char *nextPtr = NULL;
                        uint64_t base = strtoull(argv[i], &nextPtr, 16);
                        if(*nextPtr != '[' || base == 0) {
                            fprintf(stderr, "Invalid Format %s, should be base_addr[size] (base is in hex, size is not)\n", argv[i]);
                            continue;
                        }   
                        nextPtr++;
                        uint32_t size = strtoul(nextPtr, &nextPtr, 10);
                        if(*nextPtr != ']' || size == 0) {
                            fprintf(stderr, "Invalid Format %s, should be base_addr[size] (base is in hex, size is in decimal)\n", argv[i]);
                            continue;
                        }
                        bytecode.push_back(make_pair(base, size));
                    }
                    break;
                case 'd':
                    i++;
                    for(; i < argc && argv[i][0] != '-'; i++) {
                        uint64_t addr = strtoull(argv[i], NULL, 16);
                        printf("looking for %llx\n", (unsigned long long) addr);
                        if(addr != 0) {
                            dispatch.insert(addr);
                        }
                    }
                    break;
                case 't':
                    i++;
                    trace = argv[i];
                    i++;
                    break;
                case 's':
                    i++;
                    for(; i < argc && argv[i][0] != '-'; i++) {
                        sources.push_back(argv[i]);
                    }
                    break;
                case 'h':
                    printUsage(argv[0]);
                    exit(0);
                case 'c':
                    coalesce = true;
                    i++;
                    break;
                default:
                    printf("Unknown Command Line Argument %s\n", argv[i]);
                    i++;
                    break;
            }
        }
        else {
            printf("Unknown Command Line Argument %s\n", argv[i]);
            i++;
        }
    }

    return;
}

/*void getSrcTaint(TaintState *state, InsInfo *info, uint32_t tid, set<uint64_t> &taint) {
    ReaderOp *op = info->srcOps;
    for(int i = 0; i < info->srcOpCnt; i++) {
        if(op->type == REG_OP) {
            taint.insert(getCombinedRegTaint(state, (LynxReg) op->reg, tid, 0));
        }
        else if(op->type == MEM_OP) {
            taint.insert(getMemTaintLabel(state, op->mem.addr, op->mem.size, 0);

            if(op->mem.base != LYNX_INVALID) {
                taint.insert(getCombinedRegTaint(state, (LynxReg) op->mem.base, tid, 0));
            }
            if(op->mem.index != LYNX_INVALID) {
                taint.insert(getCombinedRegTaint(state, (LynxReg) op->mem.index, tid, 0));
            }
            if(op->mem.seg != LYNX_INVALID) {
                taint.insert(getCombinedRegTaint(state, (LynxReg) op->mem.seg, tid, 0));
            }
        }
    }

    ReaderOp *op = info->readWriteOps;
    for(int i = 0; i < info->readWriteCnt; i++) {
        if(op->type == REG_OP) {
            taint.insert(getCombinedRegTaint(state, (LynxReg) op->reg, tid, 0));
        }
        else if(op->type == MEM_OP) {
            taint.insert(getMemTaintLabel(state, op->mem.addr, op->mem.size, 0);

            if(op->mem.base != LYNX_INVALID) {
                taint.insert(getCombinedRegTaint(state, (LynxReg) op->mem.base, tid, 0));
            }
            if(op->mem.index != LYNX_INVALID) {
                taint.insert(getCombinedRegTaint(state, (LynxReg) op->mem.index, tid, 0));
            }
            if(op->mem.seg != LYNX_INVALID) {
                taint.insert(getCombinedRegTaint(state, (LynxReg) op->mem.seg, tid, 0));
            }
        }
    }

    ReaderOp *op = info->dstOps;
    for(int i = 0; i < dstOpCnt; i++) {
        else if(op->type == MEM_OP) {
            if(op->mem.base != LYNX_INVALID) {
                taint.insert(getCombinedRegTaint(state, (LynxReg) op->mem.base, tid, 0));
            }
            if(op->mem.index != LYNX_INVALID) {
                taint.insert(getCombinedRegTaint(state, (LynxReg) op->mem.index, tid, 0));
            }
            if(op->mem.seg != LYNX_INVALID) {
                taint.insert(getCombinedRegTaint(state, (LynxReg) op->mem.seg, tid, 0));
            }
        }
    }
}*/

int main(int argc, char *argv[]) {
    parseCommandLine(argc, argv);

    //check for current implementation
    if(trace == NULL) {
        printUsage(argv[0]);
        exit(1);
    }

    ReaderState *readerState = initReader(trace, 0);

    ReaderEvent curEvent;
    InsInfo info;
    InsInfo *curInfo = &info;
    initInsInfo(curInfo);

    set<uint64_t> activeDescriptors;
    uint32_t syscallTid;

    string openedFile;
    uint8_t checkOpenResult = 0;
    uint64_t curIns = 0;

    while(nextEvent(readerState, &curEvent)) {
        curIns++;
        if(curEvent.type ==  EXCEPTION_EVENT) {
            continue;
        }
        assert(curEvent.type == INS_EVENT);

        fetchInsInfo(readerState, &curEvent.ins, curInfo);

        /*if(checkOpenResult && curEvent.ins.tid == syscallTid) {
            checkOpenResult = 0;
            uint64_t fd = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, syscallTid));

            printf("' -- %llu\n", (unsigned long long) fd);

            int found = 0;
            int openedSize = openedFile.size();
            for(char *src : sources) {
                int srcSize = strlen(src);
                if(openedSize >= srcSize) {
                    printf("'%s' vs '%s'\n", openedFile.c_str() + openedSize - srcSize, src); 
                    if(strncmp(openedFile.data() + openedSize - srcSize, src, srcSize) == 0) {
                        found = 1;
                        break;
                    }
                }
            }
                
            if(found) {
                printf("found\n");
                activeDescriptors.insert(fd);
            }
            else {
                activeDescriptors.erase(fd);
            }
        }
        else*/ if(curInfo->insClass == XED_ICLASS_SYSCALL) {
            uint64_t callNum = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));
                
            //read
            /*if(callNum == 0) {
                uint64_t fd = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                if(activeDescriptors.find(fd) != activeDescriptors.end()) {
                    uint64_t addr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                    uint64_t size = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                    //uint64_t dataLabel = getNewLabel(forwardTaint);

                    taintMem(forwardTaint, addr, size, genericLabel);
                    if(!propagate) {
                        curInfo = new InsInfo;
                        initInsInfo(curInfo);
                        fetchInsInfo(readerState, &curEvent.ins, curInfo);
                        ops.push_back(make_pair(make_pair(curIns, make_pair(curEvent.ins.addr, curEvent.ins.tid)), curInfo));
                        propagate=1;
                    }
                    printf("reading %llu %llx[%llu]\n", (unsigned long long) fd, (unsigned long long) addr, (unsigned long long) size);
                }
            }*/
            //open
            if(callNum == 2) {
                uint64_t filename = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                openedFile.clear();

                printf("open '");

                char curChar;
                getMemoryVal(readerState, filename++, 1, (uint8_t *) &curChar);
                while(curChar != 0) {
                    printf("%c", curChar);
                    openedFile += curChar;
                    getMemoryVal(readerState, filename++, 1, (uint8_t *) &curChar);
                }

                printf(" at %lld\n", (unsigned long long) curIns);

                syscallTid = curEvent.ins.tid;
                checkOpenResult = 1;
            }
        }
    }

    closeReader(readerState);

    return 0;
}
