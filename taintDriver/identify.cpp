#include <cstdio>
#include <vector>
#include <utility>
#include <set>
#include <cassert>
#include <unordered_map>
#include <cstring>
#include <string>

using namespace std;

extern "C" {
    #include <Reader.h>
    #include <Taint.h>
}

struct pairHash {
    //std::size_t operator() (const std::pair<uint64_t, uint64_t> &p) const {
    inline std::size_t operator()(const std::pair<uint64_t, uint64_t> & p) const {
        return p.first * p.second;
    }   
};

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printf("Usage: %s <trace> <source_list>", argv[0]);
    }

    ReaderState *readerState = initReader(argv[1], 0);
    vector<char *> sources;

    for(int i = 2; i < argc; i++) {
        sources.push_back(argv[i]);
    }

    TaintState *forwardState = initTaint(readerState); 

    ReaderEvent curEvent;
    InsInfo info;
    initInsInfo(&info);

    set<uint64_t> activeDescriptors;

    string openedFile;
    uint32_t syscallTid = 0;
    uint8_t checkOpenResult = 0;
    uint64_t curIns = 0;
    uint8_t propagate = 0;

    uint64_t lastTaintedIns = 0;
    uint64_t lastTaintedAddr = 0;
    uint64_t lastTaintedSize = 0;
    uint64_t lastTaintLabel = 0;

    set<uint64_t> taintSet;

    while(nextEvent(readerState, &curEvent)) {
        curIns++;
        if(curEvent.type ==  EXCEPTION_EVENT) {
            continue;
        }
        assert(curEvent.type == INS_EVENT);

        fetchInsInfo(readerState, &curEvent.ins, &info);

        if(checkOpenResult && curEvent.ins.tid == syscallTid) {
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
        else if(info.insClass == XED_ICLASS_SYSCALL) {
            uint64_t callNum = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));
                
            //read
            if(callNum == 0) {
                uint64_t fd = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                if(activeDescriptors.find(fd) != activeDescriptors.end()) {
                    uint64_t addr = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                    uint64_t size = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                    uint64_t dataLabel = getNewLabel(forwardState);

                    taintMem(forwardState, addr, size, dataLabel);
                    propagate=1;
                    printf("reading %llu %llx[%llu]\n", (unsigned long long) fd, (unsigned long long) addr, (unsigned long long) size);
                }
            }
            //open
            else if(callNum == 2) {
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

                syscallTid = curEvent.ins.tid;
                checkOpenResult = 1;
            }
        }

        if(propagate) {
            //int makeNewTaint = 0;
            //uint64_t setTo = 0;
            ReaderOp *ops = info.srcOps;
            for(int i = 0; i < info.srcOpCnt; i++) {
                if(ops->type == MEM_OP) {
                    uint64_t taint = getMemTaintLabel(forwardState, ops->mem.addr, ops->mem.size, 0);
                    if(taint != 0) {
                        if(taintSet.find(taint) == taintSet.end()) {
                            taintOperand(forwardState, ops, curEvent.ins.tid, 0);
                            uint64_t dataLabel = getNewLabel(forwardState);
                            //printf("making new at %llu, old: %llx, new: %llx\n", curIns, taint, dataLabel);
                            taintMem(forwardState, ops->mem.addr, ops->mem.size, dataLabel);
                            //taintOperandList(forwardState, info.dstOps, info.dstOpCnt, curEvent.ins.tid, dataLabel);
                            taintSet.insert(dataLabel);
                            //taintOperandList(forwardState, info.readWriteOps, info.readWriteOpCnt, curEvent.ins.tid, 0);
                            break;
                        }
                        else {
                            //printf("found at %llu\n", curIns);
                            taintOperand(forwardState, ops, curEvent.ins.tid, 0);
                            taintMem(forwardState, ops->mem.addr, ops->mem.size, taint);
                            //setTo = taint;
                        }
                    }
                }
            }

            uint64_t taint = propagateForward(forwardState, &curEvent, &info);
            /*if(makeNewTaint) {
                makeNewTaint = 0;
            }
            else if(setTo != 0) {
                taintOperandList(forwardState, info.dstOps, info.dstOpCnt, curEvent.ins.tid, setTo);
            }*/

            if(taint) {

                if((info.insClass == XED_ICLASS_JMP || info.insClass == XED_ICLASS_JMP_FAR || info.insClass == XED_ICLASS_CALL_FAR || info.insClass == XED_ICLASS_CALL_NEAR)) {
                    //only taint indirect jumps
                    bool indirectJmp = false;
                    ReaderOp *ops = info.srcOps;
                    int i;
                    for(i = 0; i < info.srcOpCnt; i++) {
                        if((ops->type == REG_OP && ops->reg != LYNX_RIP) || ops->type == MEM_OP) {
                            indirectJmp = true;
                            break;
                        }   
                        ops = ops->next;
                    }   

                    if(indirectJmp) {
                        if(taintSet.find(taint) != taintSet.end()) {
                            printf(" > (%llx) %s %s %llu %llx %s\n", (unsigned long long) taint, fetchStrFromId(readerState, curEvent.ins.srcId), fetchStrFromId(readerState, curEvent.ins.fnId), (unsigned long long) curIns, (unsigned long long) curEvent.ins.addr, info.mnemonic);
                            //taintSet.erase(taint);
                        }
                    }   
                }
            }
        }
    }

    freeTaint(forwardState);
    closeReader(readerState);

    return 0;
}
