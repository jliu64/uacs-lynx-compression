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
    printf("* d <addr1 addr2 ...> - List of dispatch addresses\n");
    printf("* b <base1[size1] base2[size2] ...> - List identifying bytecode locations in memory\n");
    printf("  s <source1 source2 ...> - source files of interest executed by the interpereter\n");
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
    if(trace == NULL) {
        printUsage(argv[0]);
    }

    ReaderState *readerState = initReader(trace, 0);

    //initialize only if we need it
    TaintState *forwardState = NULL; 
    TaintState *backState = initTaint(readerState);

    ReaderEvent curEvent;
    InsInfo staticInfo;
    InsInfo *curInfo = &staticInfo;
    initInsInfo(curInfo);

    set<uint64_t> activeDescriptors;

    string openedFile;
    uint32_t syscallTid = 0;
    uint8_t checkOpenResult = 0;
    uint8_t storeState = 0;
    uint64_t curIns = 0;
    uint64_t activeReadLabels = 0;
    vector< pair<pair<uint64_t, pair<uint64_t, uint32_t> >, InsInfo *> > events;
    unordered_map<uint64_t, uint64_t> labelMap;
    vector< pair<uint64_t, uint64_t> > jmps;
    vector< pair<uint64_t, vector<uint64_t> > > dumps;
    uint64_t bytecodeWrite = 0;
    while(nextEvent(readerState, &curEvent)) {
        curIns++;
        if(curEvent.type ==  EXCEPTION_EVENT) {
            continue;
        }
        assert(curEvent.type == INS_EVENT);

        if(storeState) {
            curInfo = new InsInfo;
            initInsInfo(curInfo);
            fetchInsInfo(readerState, &curEvent.ins, curInfo);
            events.push_back(make_pair(make_pair(curIns, make_pair(curEvent.ins.addr, curEvent.ins.tid)), curInfo));
        }
        else {
            fetchInsInfo(readerState, &curEvent.ins, curInfo);
        }


        if(!sources.empty()) {
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

                    //if we found, we might need to propagate forward
                    if(forwardState == NULL) {
                        forwardState = initTaint(readerState);
                    }
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
                        uint64_t dataLabel = getNewLabel(forwardState);

                        activeReadLabels = mergeLabels(forwardState, dataLabel, activeReadLabels);
                        taintMem(forwardState, addr, size, dataLabel);
                        printf("reading %llu %llx[%llu]\n", (unsigned long long) fd, (unsigned long long) addr, (unsigned long long) size);
                        //start recording?
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

            if(forwardState != NULL) {
                uint64_t taint = propagateForward(forwardState, &curEvent, curInfo);
                
                if(taint && !dispatch.empty()) {
                    if((curInfo->insClass == XED_ICLASS_JMP || curInfo->insClass == XED_ICLASS_JMP_FAR || curInfo->insClass == XED_ICLASS_CALL_FAR || curInfo->insClass == XED_ICLASS_CALL_NEAR)) {// && interpId == curEvent.ins.srcId) {

                        if(dispatch.find(curEvent.ins.addr) == dispatch.end()) {
                            continue;
                        }

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

                        if(indirectJmp) {
                            uint64_t jmpLabel = getNewLabel(backState);
                            jmps.push_back(make_pair(curIns, jmpLabel));

                            if(bytecode.empty()) {
                                uint64_t wasActive = activeReadLabels;
                                activeReadLabels = subtractLabel(forwardState, taint, activeReadLabels);

                                if(wasActive != activeReadLabels) {
                                    if(!storeState) {
                                        curInfo = new InsInfo;
                                        initInsInfo(curInfo);
                                        fetchInsInfo(readerState, &curEvent.ins, curInfo);
                                        events.push_back(make_pair(make_pair(curIns, make_pair(curEvent.ins.addr, curEvent.ins.tid)), curInfo));
                                    }
                                    storeState = 1;

                                    printBaseLabels(forwardState, activeReadLabels);
                                    printBaseLabels(forwardState, wasActive);
                                    uint64_t died = subtractLabel(forwardState, activeReadLabels, wasActive);
                                    vector<uint64_t> deadLabels;

                                    printf("delete ");
                                    while(died != 0) {
                                        uint64_t label = popLabel(forwardState, &died);
                                        printf("%llx ", (unsigned long long) label);
                                        deadLabels.push_back(label);
                                    }   
                                    printf("at %llu\n", (unsigned long long) curIns);

                                    dumps.push_back(make_pair(curIns, deadLabels));
                                }   
    
                                uint64_t lastRead = popLabel(forwardState, &taint);
                                labelMap[lastRead] = mergeLabels(backState, jmpLabel, labelMap[lastRead]);
                            }
                            else {
                                if(dumps.empty() || dumps.back().first != bytecodeWrite) {
                                    vector<uint64_t> tmp;
                                    tmp.push_back(bytecodeWrite);
                                    dumps.push_back(make_pair(bytecodeWrite, tmp));
                                }

                                labelMap[bytecodeWrite] = mergeLabels(backState, jmpLabel, labelMap[bytecodeWrite]);
                            }
                        }
                    }   
                }
            }
        }
        else {
            assert(!dispatch.empty());

            if(dispatch.find(curEvent.ins.addr) != dispatch.end()) {
                uint64_t jmpLabel = getNewLabel(backState);
                jmps.push_back(make_pair(curIns, jmpLabel));
            }
        }

        if(!bytecode.empty()) {
            uint8_t found = 0;

            ReaderOp *op = curInfo->dstOps;
            for(int i = 0; i < curInfo->dstOpCnt; i++) {
                if(op->type == MEM_OP) {
                    for(pair<uint64_t, uint32_t> &region : bytecode) {
                        uint64_t offset1 = op->mem.addr - region.first;
                        uint64_t offset2 = region.first - op->mem.addr;
                        if(offset1 < region.second || offset2 < op->mem.size) {
                            found = 1;
                            break;
                        }
                    }
                }
                if(found) {
                    break;
                }
                op = op->next;
            }

            if(!found) {
                ReaderOp *op = curInfo->readWriteOps;
                for(int i = 0; i < curInfo->readWriteOpCnt; i++) {
                    if(op->type == MEM_OP) {
                        for(pair<uint64_t, uint32_t> &region : bytecode) {
                            uint64_t offset1 = op->mem.addr - region.first;
                            uint64_t offset2 = region.first - op->mem.addr;
                            if(offset1 < region.second || offset2 < op->mem.size) {
                                found = 1;
                                break;
                            }
                        }
                    }
                    if(found) {
                        break;
                    }
                    op = op->next;
                }
            }
            
            if(found) {
                if(!storeState) {
                    curInfo = new InsInfo;
                    initInsInfo(curInfo);
                    fetchInsInfo(readerState, &curEvent.ins, curInfo);
                    events.push_back(make_pair(make_pair(curIns, make_pair(curEvent.ins.addr, curEvent.ins.tid)), curInfo));
                }
                storeState = 1;

                //we want to quit right before the write
                bytecodeWrite = curIns+1;
                printf("found write at %llu\n", (unsigned long long) curIns);
            }
        }
    }

    if(forwardState != NULL) {
        freeTaint(forwardState);
    }
    unordered_map<uint64_t, uint32_t> labelThreads;
   
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
    }

    while(!events.empty() && !dumps.empty()) {
        pair<pair<uint64_t, pair<uint64_t, uint32_t > >, InsInfo *> &opPair = events.back();
        curIns = opPair.first.first;
        uint64_t addr = opPair.first.second.first;
        uint32_t tid = opPair.first.second.second;
        curInfo = opPair.second;
        events.pop_back();

        if(!jmps.empty() && curIns == jmps.back().first) {
            uint64_t jmpLabel = jmps.back().second;
            labelThreads[jmpLabel] = tid;
            jmps.pop_back();

            int i;
            ReaderOp *ops = curInfo->srcOps;
            for(i = 0; i < curInfo->srcOpCnt; i++) {
                if((ops->type == REG_OP && ops->reg != LYNX_RIP) || ops->type == MEM_OP) {
                    addTaintToOperandList(backState, curInfo->srcOps, curInfo->srcOpCnt, tid, jmpLabel);
                    addTaintToOperandList(backState, curInfo->readWriteOps, curInfo->readWriteOpCnt, tid, jmpLabel);

                    int i;
                    ReaderOp *ops = curInfo->dstOps;
                    for(i = 0; i < curInfo->dstOpCnt; i++) {
                        if(ops->type == MEM_OP) {
                            if(ops->mem.seg != LYNX_INVALID) {
                                addTaintToReg(backState, (LynxReg) ops->mem.seg, tid, jmpLabel);
                            }   
                            if(ops->mem.base != LYNX_INVALID && ops->mem.base != LYNX_RIP && ops->mem.base != LYNX_RSP) {
                                addTaintToReg(backState, (LynxReg) ops->mem.base, tid, jmpLabel);
                            }   
                            if(ops->mem.index != LYNX_INVALID && ops->mem.index != LYNX_RIP && ops->mem.index != LYNX_RSP) {
                                addTaintToReg(backState, (LynxReg) ops->mem.index, tid, jmpLabel);
                            }    
                        }    
                    }

                    printf(" > %llu %llx %llx %s\n", (unsigned long long) curIns, (unsigned long long) jmpLabel, (unsigned long long) addr, curInfo->mnemonic);
                    break;
                }
                ops = ops->next;
            }
        }
        else {
            uint64_t taint = propagateBackward(backState, tid, curInfo);
        }

        if(curIns == dumps.back().first) {
            vector<uint64_t> &reads = dumps.back().second;

            printf("deleting ");

            uint64_t kill = 0;
            for(uint64_t &read : reads) {
                kill = mergeLabels(backState, kill, labelMap[read]);
                printf("%llx ", (unsigned long long) read);
            }

            printf("at %llu(%llx)\n", (unsigned long long) curIns, (unsigned long long) kill);

            //printBaseLabels(backState, kill);

            unordered_map<uint64_t, uint64_t> insMap;
            if(bytecode.empty()) {
                uint8_t *labels = getLabelArray(backState);
                uint64_t size = getLabelArraySize(backState);

                getArchLabels(backState, labels);

                uint64_t missing = kill;
                set<uint64_t> toCondense;
                for(uint64_t i = 1; i < size; i++) {
                    if(labels[i]) {
                        uint64_t label = getLabelIntersect(backState, i, kill);
                        if(label == 0) {
                            continue;
                        }

                        if(labelSize(backState, label) == 1) {
                            toCondense.insert(label);
                            continue;
                        }

                        if(!labelHasSequential(backState, kill, label)) {
                            if(toCondense.insert(label).second) {
                                missing = subtractLabel(backState, label, missing);
                            }
                        }

                        /*uint64_t first = getFirstLabel(backState, label);
                        uint64_t last = getLastLabel(backState, label);

                        uint64_t notPresent*/
                    }
                }

                while(missing != 0) {
                    toCondense.insert(popLabel(backState, &missing));
                }

                delete[] labels;
                labels = getLabelArray(backState);

                for(const uint64_t &label : toCondense) {
                    labels[label] = 1;
                }

                uint8_t *condensed = outputCondensedLabels(backState, labels);
                delete[] labels;

                size = getLabelArraySize(backState);
                for(uint64_t i = 0; i < size; i++) {
                    if(condensed[i]) {
                        if(cfg != NULL) {
                            fprintf(cfg, " B%llu [shape=box, style=solid, label=\"%llx\"];\n", (unsigned long long) i, (unsigned long long) i);
                        }

                        uint64_t group = i;
                        while(group != 0) {
                            insMap[popLabel(backState, &group)] = i;
                        }
                    }
                }

                delete[] condensed;
            }
            else {
                uint64_t foundLabels = 0;
                for(pair<uint64_t, uint32_t> &region : bytecode) {
                    for(int i = 0; i < region.second; i++) {
                        uint64_t group = getMemTaintLabel(backState, region.first + i, 1, 0);
                        printf("%llx: %llx\n", (unsigned long long)(region.first + i), (unsigned long long) group);
                        if(group != 0) {
                            uint64_t oldFoundLabels = foundLabels;
                            foundLabels = mergeLabels(backState, foundLabels, group);
                            if(oldFoundLabels != foundLabels) {
                                uint64_t labels = group;
                                if(cfg != NULL) {
                                    fprintf(cfg, " B%llu [shape=box, style=solid, label=\"%llx\"];\n", (unsigned long long) group, (unsigned long long) group);
                                }

                                while(labels != 0) {
                                    insMap[popLabel(backState, &labels)] = group;
                                }
                            }
                            taintMem(backState, region.first + i, 1, 0);
                        }
                    }
                }

                if(foundLabels != kill) {
                    uint64_t missing = subtractLabel(backState, foundLabels, kill);
                    printf("Missing ");
                    while(missing != 0) {
                        printf("%llx ", (unsigned long long) popLabel(backState, &missing));
                    }
                    printf("\n");
                }
            }

            unordered_map< pair<uint64_t, uint64_t>, uint32_t, pairHash> controlFlow;
            unordered_map<uint32_t, uint64_t> last;
            while(kill != 0) {
                uint64_t curLabel = popLabel(backState, &kill);
                uint32_t curTid = labelThreads[curLabel];
                uint64_t curGroup = insMap[curLabel];

                controlFlow[make_pair(curGroup, last[curTid])]++;
                last[curTid] = curGroup;
            }

            for(auto it = controlFlow.begin(); it != controlFlow.end(); it++) {
                if(cfg != NULL) {
                    fprintf(cfg, " B%llu -> B%llu [style=solid, color=\"black\", label=\"%u\"];\n", (unsigned long long) it->first.first, (unsigned long long) it->first.second, it->second);
                }
            }

            dumps.pop_back();
            printf("\n////////////////////////\n\n");
        }
    }

    if(cfg != NULL) {
        fprintf(cfg, "}\n");
    }
    freeTaint(backState);
    closeReader(readerState);

    return 0;
}
