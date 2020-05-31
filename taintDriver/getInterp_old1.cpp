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

using namespace std;

extern "C" {
    #include <Reader.h>
    #include <Taint.h>
}

char *trace = NULL;
set<uint64_t> dispatch;
vector< pair<uint64_t, uint32_t> > bytecode;
vector<char *> sources;

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



int main(int argc, char *argv[]) {
    parseCommandLine(argc, argv);

    //check for current implementation
    if(trace == NULL || sources.empty()) {
        printUsage(argv[0]);
        exit(1);
    }

    ReaderState *readerState = initReader(trace, 0);
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
    uint64_t genericLabel = getNewLabel(forwardState);

    set<uint64_t> taintSet;
    //unordered_map<uint32_t, uint64_t> prevLabel;
    //unordered_map<pair<uint64_t, uint64_t>, uint32_t, pairHash> controlFlow;
    unordered_map<uint64_t, uint64_t> labelMap;
    unordered_map<uint32_t, vector< pair<uint64_t, uint64_t> > > labelSeq;
    set<uint32_t> tids;
    uint64_t world = genericLabel;
    unordered_map<uint64_t, uint32_t> labelSizes;

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
                    //uint64_t dataLabel = getNewLabel(forwardState);

                    taintMem(forwardState, addr, size, genericLabel);
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
            uint64_t memTaint = 0;
            ReaderOp *ops = info.srcOps;
            for(int i = 0; i < info.srcOpCnt; i++) {
                if(ops->type == MEM_OP) {
                    uint64_t taint = getMemTaintLabel(forwardState, ops->mem.addr, ops->mem.size, 0);
                    if(taint != 0) {
                        //printf("read %llx from %llu at %llu\n", taint, labelMap[taint], curIns);
                        //taintOperand(forwardState, ops, curEvent.ins.tid, 0);
                        //taintMem(forwardState, ops->mem.addr, ops->mem.size, taint);
                        
                        int found = bytecode.empty();
                        for(pair<uint64_t, uint32_t> &region : bytecode) {
                            uint64_t offset1 = ops->mem.addr - region.first;
                            uint64_t offset2 = region.first - ops->mem.addr;
                            if(offset1 < region.second || offset2 < ops->mem.size) {
                                found = 1;
                                break;
                            }
                        }
                        if(found) {
                            if(labelSizes.find(taint) == labelSizes.end() || labelSizes[taint] != ops->mem.size) {
                                //taintOperand(forwardState, ops, curEvent.ins.tid, 0);
                                uint64_t dataLabel = getNewLabel(forwardState);
                                labelMap[dataLabel] = curIns;
                                labelSizes[dataLabel] = ops->mem.size;
                                //printf("making new at %llu, old: %llx, new: %llx\n", curIns, taint, dataLabel);
                                taintMem(forwardState, ops->mem.addr, ops->mem.size, dataLabel);
                                memTaint = dataLabel;
                                //taintOperandList(forwardState, info.dstOps, info.dstOpCnt, curEvent.ins.tid, dataLabel);
                                //taintSet.insert(dataLabel);
                                //taintOperandList(forwardState, info.readWriteOps, info.readWriteOpCnt, curEvent.ins.tid, 0);
                                break;
                            }
                            else {
                                //printf("%llu: %llx[%u] vs %u\n", curIns, taint, labelSize[taint], ops->mem.size);
                                //printf("found at %llu\n", curIns);
                                //taintOperand(forwardState, ops, curEvent.ins.tid, 0);
                                //taintMem(forwardState, ops->mem.addr, ops->mem.size, taint);
                                memTaint = taint;
                                //setTo = taint;
                            }
                        }
                    }
                }
            }

            uint64_t taint;
            if(memTaint != 0) {
                taint = memTaint;
                taintOperandList(forwardState, info.dstOps, info.dstOpCnt, curEvent.ins.tid, memTaint);
                taintOperandList(forwardState, info.readWriteOps, info.readWriteOpCnt, curEvent.ins.tid, memTaint);
            }
            else {
                taint = propagateForward(forwardState, &curEvent, &info);
            }

            if(taint != 0) {
                ReaderOp *ops = info.readWriteOps;
                for(int i = 0; i < info.readWriteOpCnt; i++) {
                    if(ops->type == MEM_OP) {
                        /*int found = bytecode.empty();
                        for(pair<uint64_t, uint32_t> &region : bytecode) {
                            uint64_t offset1 = ops->mem.addr - region.first;
                            uint64_t offset2 = region.first - ops->mem.addr;
                            if(offset1 < region.second || offset2 < ops->mem.size) {
                                found = 1;
                                break;
                            }
                        }
                        if(found) {
                            //if(taintSet.find(taint) == taintSet.end()) {
                            if(!labelIsSubsetOf(forwardState, taint, world)) {
                                uint64_t dataLabel = getNewLabel(forwardState);
                                labelMap[dataLabel] = curIns;
                                //printf("making new at %llu, old: %llx, new: %llx\n", curIns, taint, dataLabel);
                                taintMem(forwardState, ops->mem.addr, ops->mem.size, dataLabel);
                                //taintOperandList(forwardState, info.dstOps, info.dstOpCnt, curEvent.ins.tid, dataLabel);
                                taintSet.insert(dataLabel);
                                //taintOperandList(forwardState, info.readWriteOps, info.readWriteOpCnt, curEvent.ins.tid, 0);
                                break;
                            }
                            else {
                                //printf("found at %llu\n", curIns);
                                taintMem(forwardState, ops->mem.addr, ops->mem.size, taint);
                                //setTo = taint;
                            }
                        }*/
                        /*if(taint != genericLabel) {
                            taintMem(forwardState, ops->mem.addr, ops->mem.size, genericLabel);
                        }*/
                            /*for(int i = 0; i < ops->mem.size; i++) {
                                uint64_t dataLabel = getNewLabel(forwardState);
                                labelMap[dataLabel] = curIns;
                                taintMem(forwardState, ops->mem.addr + i, 1, dataLabel);
                                //taintSet.insert(dataLabel);
                                //world = mergeLabels(forwardState, dataLabel, world);
                            }*/
                    }
                }
                ops = info.dstOps;
                for(int i = 0; i < info.dstOpCnt; i++) {
                    //if(ops->type == MEM_OP) {
                    if(ops->type == MEM_OP) {
                        /*int found = bytecode.empty();
                        for(pair<uint64_t, uint32_t> &region : bytecode) {
                            uint64_t offset1 = ops->mem.addr - region.first;
                            uint64_t offset2 = region.first - ops->mem.addr;
                            if(offset1 < region.second || offset2 < ops->mem.size) {
                                found = 1;
                                break;
                            }
                        }
                        if(found) {
                            //if(taintSet.find(taint) == taintSet.end()) {
                            if(!labelIsSubsetOf(forwardState, taint, world)) {
                                uint64_t dataLabel = getNewLabel(forwardState);
                                labelMap[dataLabel] = curIns;
                                //printf("making new at %llu, old: %llx, new: %llx\n", curIns, taint, dataLabel);
                                taintMem(forwardState, ops->mem.addr, ops->mem.size, dataLabel);
                                //taintOperandList(forwardState, info.dstOps, info.dstOpCnt, curEvent.ins.tid, dataLabel);
                                taintSet.insert(dataLabel);
                                //taintOperandList(forwardState, info.readWriteOps, info.readWriteOpCnt, curEvent.ins.tid, 0);
                                break;
                            }
                            else {
                                //printf("found at %llu\n", curIns);
                                taintMem(forwardState, ops->mem.addr, ops->mem.size, taint);
                                //setTo = taint;
                            }
                        }*/
                        /*if(taint != genericLabel) {
                            taintMem(forwardState, ops->mem.addr, ops->mem.size, genericLabel);
                        }*/
                            /*for(int i = 0; i < ops->mem.size; i++) {
                                uint64_t dataLabel = getNewLabel(forwardState);
                                labelMap[dataLabel] = curIns;
                                taintMem(forwardState, ops->mem.addr + i, 1, dataLabel);
                                //taintSet.insert(dataLabel);
                                //world = mergeLabels(forwardState, dataLabel, world);
                            }*/
                    }
                }
            }
            /*if(makeNewTaint) {
                makeNewTaint = 0;
            }
            else if(setTo != 0) {
                taintOperandList(forwardState, info.dstOps, info.dstOpCnt, curEvent.ins.tid, setTo);
            }*/

            //if(taint) {
            if(taint && (info.insClass == XED_ICLASS_JMP || info.insClass == XED_ICLASS_JMP_FAR || info.insClass == XED_ICLASS_CALL_FAR || info.insClass == XED_ICLASS_CALL_NEAR) && (dispatch.empty() || dispatch.find(curEvent.ins.addr) != dispatch.end())) {
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

                //if(indirectJmp) {// && labelIsSubsetOf(forwardState, taint, world)) {
                if(indirectJmp && taint != genericLabel && labelSize(forwardState, taint) == 1) {
                    printf(" > (%llx:%llu) %s %s %llu %llx %s\n", (unsigned long long) taint, labelMap[taint], fetchStrFromId(readerState, curEvent.ins.srcId), fetchStrFromId(readerState, curEvent.ins.fnId), (unsigned long long) curIns, (unsigned long long) curEvent.ins.addr, info.mnemonic);
                    labelSeq[curEvent.ins.tid].push_back(make_pair(taint, curEvent.ins.addr));
                    tids.insert(curEvent.ins.tid);
                    //world = mergeLabels(forwardState, world, taint);
                    //controlFlow[make_pair(prevLabel[curEvent.ins.tid], taint)]++;
                    //prevLabel[curEvent.ins.tid] = taint;
                }   
            }
        }
    }

    unordered_map<pair<uint64_t, uint64_t>, uint32_t, pairHash> controlFlow;
    set<uint64_t> removeLabels;
    set<uint64_t> removeAddrs;

    bool changed = true;
    while(changed) {
        changed = false;
        controlFlow.clear();

        for(uint32_t tid : tids) {
            uint64_t prevLabel = 0;
            auto it = labelSeq[tid].begin();
            while(it != labelSeq[tid].end()) {
                if(!changed) {
                    controlFlow[make_pair(prevLabel, it->first)]++;
                }

                if(removeLabels.find(it->first) != removeLabels.end()) {
                    it = labelSeq[tid].erase(it);
                    changed = true;
                }
                else if(removeAddrs.find(it->second) != removeAddrs.end()) {
                    it = labelSeq[tid].erase(it);
                    changed = true;
                }
                else if(it->first == prevLabel) {
                    removeLabels.insert(prevLabel);
                    removeAddrs.insert(it->second);
                    it = labelSeq[tid].erase(it);
                    changed = true;
                }
                else {
                    prevLabel = it->first;
                    it++;
                }
            }
        }
    }

    int nameSize = strlen(trace);
    char *cfgFilename = new char[nameSize + 5]();
    strncpy(cfgFilename, trace, nameSize);
    strncpy(cfgFilename + nameSize, ".dot", 4);
    FILE *cfg = fopen(cfgFilename, "w");
    if(cfg == NULL) {
        fprintf(stderr, "Could not open cfg file\n");
    }
    else {
        fprintf(cfg, "digraph \"G\" {\n");
        set<uint64_t> blocks;
        for(auto it = controlFlow.begin(); it != controlFlow.end(); it++) {
            if(blocks.find(it->first.first) == blocks.end()) {
                blocks.insert(it->first.first);
                fprintf(cfg, " B%llu [shape=box, style=solid, label=\"%llx\"];\n", (unsigned long long) it->first.first, (unsigned long long) it->first.first);
            }

            if(blocks.find(it->first.second) == blocks.end()) {
                blocks.insert(it->first.second);
                fprintf(cfg, " B%llu [shape=box, style=solid, label=\"%llx\"];\n", (unsigned long long) it->first.second, (unsigned long long) it->first.second);
            }

            fprintf(cfg, " B%llu -> B%llu [style=solid, color=\"black\", label=\"%u\"];\n", (unsigned long long) it->first.first, (unsigned long long) it->first.second, it->second);
        }
        fprintf(cfg, "}\n");
    }


    freeTaint(forwardState);
    closeReader(readerState);

    return 0;
}
