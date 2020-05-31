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
    uint64_t curIns = 0;

    while(nextEvent(readerState, &curEvent)) {
        curIns++;
    }

    printf("%lld Instructions\n", (unsigned long long) curIns);

    closeReader(readerState);

    return 0;
}
