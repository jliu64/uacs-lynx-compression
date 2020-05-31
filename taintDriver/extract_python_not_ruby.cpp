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
    if(trace == NULL || sources.empty()) {
        printUsage(argv[0]);
        exit(1);
    }

    ReaderState *readerState = initReader(trace, 0);
    TaintState *forwardTaint = initTaint(readerState); 
    TaintState *dispatchTaint = initTaint(readerState);
    TaintState *backTaint = initTaint(readerState);

    ReaderEvent curEvent;
    InsInfo info;
    InsInfo *curInfo = &info;
    initInsInfo(curInfo);

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
    uint64_t genericLabel = getNewLabel(forwardTaint);

    set<uint64_t> taintSet;
    //unordered_map<uint32_t, uint64_t> prevLabel;
    vector< pair<uint64_t, uint64_t> > jmps;
    vector< pair<pair<uint64_t, pair<uint64_t, uint32_t> >, InsInfo *> > ops;
    vector< pair<uint64_t, uint64_t> > dispatches;
    unordered_map<uint64_t, uint64_t> labelMap;
    unordered_map<uint32_t, vector< pair<uint64_t, uint64_t> > > labelSeq;
    set<uint32_t> tids;
    uint64_t world = genericLabel;
    unordered_map<uint64_t, uint32_t> labelSizes;

    unordered_map<uint64_t, uint64_t> identities;

    while(nextEvent(readerState, &curEvent)) {
        curIns++;
        if(curEvent.type ==  EXCEPTION_EVENT) {
            continue;
        }
        assert(curEvent.type == INS_EVENT);

        if(propagate) {
            curInfo = new InsInfo;
            initInsInfo(curInfo);
            ops.push_back(make_pair(make_pair(curIns, make_pair(curEvent.ins.addr, curEvent.ins.tid)), curInfo));
        }

        fetchInsInfo(readerState, &curEvent.ins, curInfo);

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
        else if(curInfo->insClass == XED_ICLASS_SYSCALL) {
            uint64_t callNum = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));
                
            //read
            if(callNum == 0) {
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
            LynxReg segReg = LYNX_INVALID;
            uint64_t segTaint = 0;
            LynxReg baseReg = LYNX_INVALID;
            uint64_t baseTaint = 0;
            LynxReg indexReg = LYNX_INVALID;
            uint64_t indexTaint = 0;
            ReaderOp *reads[32];

            int num = getMemReads(curInfo, reads);
            if(num == 1) {
                ReaderOp *op = reads[0];
                if((op->mem.base != LYNX_INVALID && op->mem.base != LYNX_RIP && op->mem.base != LYNX_RSP) || (op->mem.index != LYNX_INVALID && op->mem.index != LYNX_RIP && op->mem.index != LYNX_RSP)) {
                    uint64_t taint = getMemTaintLabel(forwardTaint, op->mem.addr, op->mem.size, 0);
                    if(taint != 0) {
                        int found = bytecode.empty();
                        for(pair<uint64_t, uint32_t> &region : bytecode) {
                            uint64_t offset1 = op->mem.addr - region.first;
                            uint64_t offset2 = region.first - op->mem.addr;
                            if(offset1 < region.second || offset2 < op->mem.size) {
                                found = 1;
                                break;
                            }
                        }
                        if(found) {
                            if(labelSizes.find(taint) == labelSizes.end() || labelSizes[taint] != op->mem.size) {
                                uint64_t dataLabel = getNewLabel(forwardTaint);
                                labelMap[dataLabel] = curIns;
                                labelSizes[dataLabel] = op->mem.size;
                                printf("making new at %llu, old: %llx, new: %llx(%u)\n", (unsigned long long) curIns, (unsigned long long) taint, (unsigned long long) dataLabel, op->mem.size);
                                taintMem(forwardTaint, op->mem.addr, op->mem.size, dataLabel);
                            }
                            else {
                                printf("reuse at %llu: %llx(%u)\n", (unsigned long long) curIns, (unsigned long long) taint, labelSizes[taint]);
                            }

                            uint64_t identity = getNewLabel(dispatchTaint);
                            identities[identity] = curIns;
                            taintOperandList(dispatchTaint, curInfo->srcOps, curInfo->srcOpCnt, curEvent.ins.tid, 0);
                            taintOperandList(dispatchTaint, curInfo->readWriteOps, curInfo->readWriteOpCnt, curEvent.ins.tid, 0);
                            taintOperandList(dispatchTaint, curInfo->dstOps, curInfo->dstOpCnt, curEvent.ins.tid, 0);
                            
                            taintMem(dispatchTaint, op->mem.addr, op->mem.size, identity);

                            if(op->mem.base != LYNX_INVALID && op->mem.base != LYNX_RIP && op->mem.base != LYNX_RSP) {
                                baseReg = (LynxReg) op->mem.base;
                                baseTaint = getCombinedRegTaint(forwardTaint, (LynxReg)op->mem.base, curEvent.ins.tid, 0);

                                if(baseTaint != 0) {
                                    //addrTaint = baseTaint;
                                    taintReg(forwardTaint, baseReg, curEvent.ins.tid, 0);
                                }
                            }

                            if(op->mem.index != LYNX_INVALID && op->mem.index != LYNX_RIP && op->mem.index != LYNX_RSP) {
                                indexTaint = getCombinedRegTaint(forwardTaint, (LynxReg)op->mem.index, curEvent.ins.tid, 0);
                                indexReg = (LynxReg) op->mem.index;

                                if(indexTaint != 0) {
                                    //addrTaint = mergeLabels(forwardTaint, addrTaint, indexTaint);
                                    taintReg(forwardTaint, indexReg, curEvent.ins.tid, 0);
                                }
                            }

                            if(op->mem.seg != LYNX_INVALID) {
                                segTaint = getCombinedRegTaint(forwardTaint, (LynxReg)op->mem.seg, curEvent.ins.tid, 0);
                                segReg = (LynxReg) op->mem.seg;

                                if(segTaint != 0) {
                                    //addrTaint = mergeLabels(forwardTaint, addrTaint, segTaint);
                                    taintReg(forwardTaint, segReg, curEvent.ins.tid, 0);
                                }
                            }   
                        }
                    }
                }
            }

            uint64_t taint = propagateForward(forwardTaint, &curEvent, curInfo);
            uint64_t identTaint = propagateForward(dispatchTaint, &curEvent, curInfo);

            if(segTaint != 0) {
                addTaintToReg(forwardTaint, segReg, curEvent.ins.tid, segTaint);
            }
            if(indexTaint != 0) {
                addTaintToReg(forwardTaint, indexReg, curEvent.ins.tid, indexTaint);
            }
            if(baseTaint != 0) {
                addTaintToReg(forwardTaint, baseReg, curEvent.ins.tid, baseTaint);
            }

            if(taint && (curInfo->insClass == XED_ICLASS_JMP || curInfo->insClass == XED_ICLASS_JMP_FAR || curInfo->insClass == XED_ICLASS_CALL_FAR || curInfo->insClass == XED_ICLASS_CALL_NEAR) && (dispatch.empty() || dispatch.find(curEvent.ins.addr) != dispatch.end())) {
                //only taint indirect jumps
                bool indirectJmp = false;
                ReaderOp *ops = curInfo->srcOps;
                int i;
                for(i = 0; i < curInfo->srcOpCnt; i++) {
                    if((ops->type == REG_OP && ops->reg != LYNX_RIP) || ops->type == MEM_OP) {
                        indirectJmp = true;
                        break;
                    }   
                    ops = ops->next;
                }   

                //make dispatch taint propagate same way forward taint does? I.e. don't zero everything when new?
                if(indirectJmp && taint != genericLabel && labelSize(forwardTaint, taint) == 1 && labelSize(dispatchTaint, identTaint) == 1) {
                    //assert(labelSize(dispatchTaint, identTaint) == 1);
                    printf(" > [%llu](%llx:%llu) %s %s %llu %llx %s\n", (unsigned long long) identities[identTaint], (unsigned long long) taint, (unsigned long long) labelMap[taint], fetchStrFromId(readerState, curEvent.ins.srcId), fetchStrFromId(readerState, curEvent.ins.fnId), (unsigned long long) curIns, (unsigned long long) curEvent.ins.addr, curInfo->mnemonic);
                    labelSeq[curEvent.ins.tid].push_back(make_pair(taint, curEvent.ins.addr));
                    tids.insert(curEvent.ins.tid);
                    jmps.push_back(make_pair(curIns, taint));
                    dispatches.push_back(make_pair(identities[identTaint], taint));
                    //world = mergeLabels(forwardTaint, world, taint);
                    //controlFlow[make_pair(prevLabel[curEvent.ins.tid], taint)]++;
                    //prevLabel[curEvent.ins.tid] = taint;
                }   
            }
        }
    }

    unordered_map<uint64_t, uint64_t> vip;
    unordered_map<pair<uint64_t, uint64_t>, uint32_t, pairHash> controlFlow;
    uint64_t active = 0;
    while(!ops.empty()) {
        pair<pair<uint64_t, pair<uint64_t, uint32_t> >, InsInfo *> &opPair = ops.back();
        set<uint64_t> seenSubsets;
        uint64_t curIns = opPair.first.first;
        uint64_t addr = opPair.first.second.first;
        uint32_t tid = opPair.first.second.second;
        InsInfo *info = opPair.second;
        ops.pop_back();

        

        uint64_t taint = propagateBackward(backTaint, tid, info);
        if(!dispatches.empty() && curIns == dispatches.back().first) {
            pair<uint64_t, uint64_t> curDispatch = dispatches.back();
            dispatches.pop_back();

            if(dispatches.empty() || curDispatch.first != dispatches.back().first) {
                ReaderOp *op;
                getMemReads(info, &op);

                //printf(" < %llu %llx %s\n", (unsigned long long) curIns, (unsigned long long) addr, info->mnemonic);

                uint64_t dispatchLabel = 0; 

                LynxReg baseReg = LYNX_INVALID;
                if(op->mem.base != LYNX_INVALID && op->mem.base != LYNX_RIP && op->mem.base != LYNX_RSP) {
                    baseReg = (LynxReg) op->mem.base;
                    dispatchLabel = getCombinedRegTaint(backTaint, (LynxReg)op->mem.base, tid, dispatchLabel);
                }

                LynxReg indexReg = LYNX_INVALID;
                if(op->mem.index != LYNX_INVALID && op->mem.index != LYNX_RIP && op->mem.index != LYNX_RSP) {
                    indexReg = (LynxReg) op->mem.index;
                    dispatchLabel = getCombinedRegTaint(backTaint, (LynxReg)op->mem.index, tid, dispatchLabel);
                }

                LynxReg segReg = LYNX_INVALID;
                if(op->mem.seg != LYNX_INVALID) {
                    segReg = (LynxReg) op->mem.seg;
                    dispatchLabel = getCombinedRegTaint(backTaint, (LynxReg)op->mem.seg, tid, dispatchLabel);
                }

                dispatchLabel = getLabelIntersect(backTaint, active, dispatchLabel);
                active = subtractLabel(backTaint, dispatchLabel, active);

                uint64_t curLabel = getNewLabel(backTaint);
                vip[curLabel] = curDispatch.second;
                active = mergeLabels(backTaint, active, curLabel);

                printf("%llx: %llu %llx %s\n", (unsigned long long) curLabel, (unsigned long long) curIns, (unsigned long long) addr, info->mnemonic);

                printf(" < connecting %llx to ", (unsigned long long) curLabel);
                while(dispatchLabel != 0) {
                    uint64_t connection = popLabel(backTaint, &dispatchLabel);
                    printf("%llx ", (unsigned long long) connection);
                    controlFlow[make_pair(curDispatch.second, vip[connection])]++;
                }
                printf("\n");

                if(baseReg != LYNX_INVALID) {
                    taintReg(backTaint, baseReg, tid, curLabel);
                }

                if(indexReg != LYNX_INVALID) {
                    taintReg(backTaint, indexReg, tid, curLabel);
                }

                if(segReg != LYNX_INVALID) {
                    taintReg(backTaint, segReg, tid, curLabel);
                }
            }
            else {
                while(!dispatches.empty() && curDispatch.first == dispatches.back().first) {
                    dispatches.pop_back();
                }
            }
        }
    }

    /*unordered_map<uint64_t, uint64_t> vips;
    unordered_map<uint64_t, uint64_t> jmpMap;

    while(!ops.empty()) {
        pair<pair<uint64_t, pair<uint64_t, uint32_t> >, InsInfo *> &opPair = ops.back();
        set<uint64_t> seenSubsets;
        uint64_t curIns = opPair.first.first;
        uint64_t addr = opPair.first.second.first;
        uint32_t tid = opPair.first.second.second;
        InsInfo *info = opPair.second;
        ops.pop_back();

        uint64_t taint = propagateBackward(backTaint, tid, info);

        if(!jmps.empty() && curIns == jmps.back().first) {
            pair<uint64_t, uint64_t> &curJmp = jmps.back();
            uint64_t jmpLabel = getNewLabel(backTaint);
            addTaintToOperandList(backTaint, info->srcOps, info->srcOpCnt, tid, jmpLabel);
            addTaintToOperandList(backTaint, info->readWriteOps, info->readWriteOpCnt, tid, jmpLabel);
            addTaintToAddrCalcList(backTaint, info->dstOps, info->dstOpCnt, tid, jmpLabel);
            jmpMap[jmpLabel] = curJmp.second;
            printf(" < (%llx=%llx) %llu %s\n", (unsigned long long) jmpLabel, (unsigned long long) curJmp.second, (unsigned long long) curIns, info->mnemonic);
            vips[jmpLabel] = jmpLabel;
            jmps.pop_back();
        }
        else {
            if(taint == 0 || graphs.empty() || vips.find(taint) != subgraphs.end()) {
                //printf("empty\n");
                continue;
            }

            set<uint64_t> included;
            uint64_t total = 0;
            int found = 0;
            for(auto it = graphs.begin(); it != graphs.end(); it++) {
                if(labelIsSubsetOf(backTaint, *it, taint)) {
                    included.insert(*it);
                    total = mergeLabels(backTaint, total, *it);
                }
                else if(labelIsSubsetOf(backTaint, taint, *it)) {
                    found = 1;
                    break;
                }
            }

            if(found) {
                printf("found matching graph for %llx\n", (unsigned long long) taint);
                subgraphs.insert(taint);
                continue;
            }

            if(total == 0 || !labelIsSubsetOf(backTaint, taint, total)) {
                printf("didnt find subset\n");
                continue;
            }


            printf("Merging ");
            set<uint64_t> nodes;
            for(auto it = included.begin(); it != included.end(); it++) {
                printf("%llx ", (unsigned long long)*it);
                graphs.erase(*it);
                nodes.insert(getLastLabel(backTaint, *it));
            }

            printf("into %llx\n", (unsigned long long) total);
            fflush(stdout);

            uint64_t from = *nodes.rbegin();
            nodes.erase(*nodes.rbegin());

            for(uint64_t to : nodes) {
                controlFlow[make_pair(jmpMap[from], jmpMap[to])]++;
            }

            graphs.insert(total);
            subgraphs.insert(total);
        }
    }*/

    /*set<uint64_t> removeLabels;
    //set<uint64_t> removeAddrs;

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
                else if(it->first == prevLabel || labelSizes[it->first] != 1) {
                    removeLabels.insert(prevLabel);
                    it = labelSeq[tid].erase(it);
                    changed = true;
                }
                else {
                    prevLabel = it->first;
                    it++;
                }
            }
        }
    }*/

    /*auto it = controlFlow.begin();
    while(it != controlFlow.end()) {
        if(it->first.first == 0) {
            it = controlFlow.erase(it);
        }
        else {
            it++;
        }
    }*/

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


    freeTaint(forwardTaint);
    closeReader(readerState);

    return 0;
}
