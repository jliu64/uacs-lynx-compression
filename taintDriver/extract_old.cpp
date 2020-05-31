/**
 * This is the driver for the trace2ascii tool. Most of the work is done by the reader. In here, we just get
 * instructions one by one and print out the information to STDOUT. It should be noted that we are currently
 * only printing out an instruction's: address, source name, function name, thread id, bytes and mnemonic.
 **/

#include <cstdio>
#include <vector>
#include <utility>
#include <unordered_set>
#include <set>
#include <cassert>
#include <unordered_map>


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
    if(argc < 4) {
        fprintf(stderr, "Usage: %s <trace> <interpSrc> <srcFile> [hints]\n", argv[0]);
        return 1;
    }

    set<uint64_t> dispatchAddrs;

    if(argc > 4) {
        for(int i = 4; i < argc; i++) {
            uint64_t dispatchAddr = strtoull(argv[i], NULL, 16);
            if(dispatchAddr != 0) {
                dispatchAddrs.insert(dispatchAddr);
            }
        }
    }

    ReaderState *readerState = initReader(argv[1], 0);
    TaintState *forwardState = initTaint(readerState);
    TaintState *backState = initTaint(readerState);

    char *srcFile = argv[3];
    int srcFileLen = strlen(argv[3]);
    char *strBuf = new char[srcFileLen + 1];

    ReaderEvent curEvent;
    char first = 1;

    uint32_t interpId;
    bool found = false;
    uint32_t id = findString(readerState, argv[2]);
        
    if(id != -1) {
        found = true;
        interpId = id;
    }

    if(!found) {
        printf("Could not find given interpreter source\n");
        exit(1);
    }

    uint8_t addrSize = getAddrSize(readerState);

    vector< pair<pair<uint64_t, pair<uint64_t, uint32_t> >, InsInfo *> > ops;

    //vector<pair<uint64_t, uint32_t>> memRead;
    vector< pair<uint64_t, uint64_t> > jmps;
    vector< pair<uint64_t, vector<uint64_t> > > dumps;

    //can't do the read thing, instead propagate taint to jumps and mark which jumps to clean up

    uint64_t activeReadLabels = 0;
    //int start = 0;
    //int stopAtNext = 0;
    uint64_t curIns = 0;
    unordered_map<uint64_t, uint64_t> labelMap;

    char printSyscallReturn = 0;
    uint32_t syscallTid = 0;
    int fd = -1;
    int record = 0;

    while(nextEvent(readerState, &curEvent)) {
        if(curEvent.type == EXCEPTION_EVENT) {
            continue;
        }

        curIns++;
        assert(curEvent.type == INS_EVENT);

        //save info for backward taint analysis
        InsInfo *info = new InsInfo;
        initInsInfo(info);
        fetchInsInfo(readerState, &curEvent.ins, info);

        if(printSyscallReturn && curEvent.ins.tid == syscallTid) {
            uint64_t rax = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));
            printf("%llu\n", (unsigned long long) rax);
            printSyscallReturn = 0;

            if(strncmp(strBuf, srcFile, srcFileLen) == 0) {
                fd = rax;      
            }
            else if(rax == fd) {
                fd = -1;
            }
        }

        //taint read system calls
        if(info->insClass == XED_ICLASS_SYSCALL) {
            uint64_t rax = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));

            if(rax == 0) {
                uint64_t rdi = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));
                if(rdi == fd) {
                    uint64_t rdx = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                    uint64_t rsi = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                    uint64_t dataLabel = getNewLabel(forwardState);
                    printf("Reading %llu into %llx %llu at %llu, marking %llx\n", (unsigned long long) rdi, (unsigned long long)rsi, (unsigned long long)rdx, (unsigned long long)curIns, (unsigned long long)dataLabel);

                    activeReadLabels = mergeLabels(forwardState, dataLabel, activeReadLabels);
                    taintMem(forwardState, rsi, rdx, dataLabel);
                    record = 1;
                }
            }   
            else if(rax == 2) {
                uint64_t rdi = *((uint64_t *) getRegisterVal(readerState, LYNX_RDI, curEvent.ins.tid));

                printf("open '");
                char pathChar;

                getMemoryVal(readerState, rdi, srcFileLen, (uint8_t *) strBuf);

                getMemoryVal(readerState, rdi++, 1, (uint8_t *) &pathChar);
                while(pathChar != 0) {
                    printf("%c", pathChar);
                    getMemoryVal(readerState, rdi++, 1, (uint8_t *) &pathChar);
                };

                printf("' -- ");
                printSyscallReturn = 1;
                syscallTid = curEvent.ins.tid;
            }
        }   
 
        //propagate taint to jumps
        uint64_t taint = propagateForward(forwardState, &curEvent, info);
        if(taint) {
            if((info->insClass == XED_ICLASS_JMP || info->insClass == XED_ICLASS_JMP_FAR || info->insClass == XED_ICLASS_CALL_FAR || info->insClass == XED_ICLASS_CALL_NEAR) && interpId == curEvent.ins.srcId) {

                if(!dispatchAddrs.empty() && dispatchAddrs.find(curEvent.ins.addr) == dispatchAddrs.end()) {
                    continue;
                }

                //only taint indirect jumps
                bool indirectJmp = false;
                ReaderOp *ops = info->srcOps;
                int i;
                for(i = 0; i < info->srcOpCnt; i++) {
                    if((ops->type == REG_OP && ops->reg != LYNX_RIP) || ops->type == MEM_OP) {
                        indirectJmp = true;
                        break;
                    }
                    ops = ops->next;
                }

                if(indirectJmp) {
                    uint64_t jmpLabel = getNewLabel(backState);
                    jmps.push_back(make_pair(curIns, jmpLabel));

                    uint64_t wasActive = activeReadLabels;
                    activeReadLabels = subtractLabel(forwardState, taint, activeReadLabels);

                    if(wasActive != activeReadLabels) {
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
            }
        }

        if(record) {
            ops.push_back(make_pair(make_pair(curIns, make_pair(curEvent.ins.addr, curEvent.ins.tid)), info));
        }
        else {
            freeInsInfo(info);
            delete info;
        }
    }

    freeTaint(forwardState);
    unordered_map<uint64_t, uint32_t> labelThreads;

    int nameSize = strlen(argv[1]);
    char *cfgFilename = new char[nameSize + 5];
    strncpy(cfgFilename, argv[1], nameSize);
    strncpy(cfgFilename + nameSize, ".dot", 4);

    FILE *cfg = fopen(cfgFilename, "w");
    if(cfg == NULL) {
        fprintf(stderr, "Could not open cfg file\n");
    }

    if(cfg != NULL) {
        fprintf(cfg, "digraph \"G\" {\n");
    }

    while(!ops.empty()) {
        pair<pair<uint64_t, pair<uint64_t, uint32_t> >, InsInfo *> &opPair = ops.back();
        uint64_t curIns = opPair.first.first;
        uint64_t addr = opPair.first.second.first;
        uint32_t tid = opPair.first.second.second;
        InsInfo *info = opPair.second;
        ops.pop_back();

        /*if(curIns % 1000000 == 0) {
            uint8_t *alive = getLabelArray(taintState);
            for(int i = 0; i < maxLabel; i++) {
                alive[i] = 1;
            }
            recoverSpace(taintState, alive);
            delete[] alive;
        }*/

        if(!jmps.empty() && curIns == jmps.back().first) {
            uint64_t jmpLabel = jmps.back().second;
            labelThreads[jmpLabel] = tid;
            jmps.pop_back();
            ReaderOp *ops = info->srcOps;
            int i;
            for(i = 0; i < info->srcOpCnt; i++) {
                if((ops->type == REG_OP && ops->reg != LYNX_RIP) || ops->type == MEM_OP) {
                    // uint64_t label = getNewLabel(taintState);
                    addTaintToOperandList(backState, info->srcOps, info->srcOpCnt, tid, jmpLabel);
                    addTaintToOperandList(backState, info->readWriteOps, info->readWriteOpCnt, tid, jmpLabel);

                    int i;
                    ReaderOp *ops = info->dstOps;
                    for(i = 0; i < info->dstOpCnt; i++) {
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
                    printf(" > %llu %llx %llx %s\n", (unsigned long long) curIns, (unsigned long long) jmpLabel, (unsigned long long) addr, info->mnemonic);
                    break;
                }
                ops = ops->next;
            }
        }
        else {
            uint64_t taint = propagateBackward(backState, tid, info);
        }


        if(!dumps.empty() && curIns == dumps.back().first) {
            vector<uint64_t> &reads = dumps.back().second;

            printf("deleting ");

            uint64_t kill = 0;
            for(uint64_t &read : reads) {
                printf("%llx ", (unsigned long long) read);
                kill = mergeLabels(backState, kill, labelMap[read]);
            }

            printf("at %llu\n", (unsigned long long) curIns);

            printBaseLabels(backState, kill);

            uint8_t *labels = getLabelArray(backState);
            uint64_t size = getNewLabel(backState);

            getArchLabels(backState, labels);

            uint64_t missing = kill;
            set<uint64_t> toCondense;
            for(uint64_t i = 1; i < size; i++) {
                if(labels[i]) {
                    //intersect with kill labels
                    uint64_t label = getLabelIntersect(backState, i, kill);
                    if(label == 0) {
                        continue;
                    }

                    //if one label, continue
                    if(labelSize(backState, label) == 1) {
                        toCondense.insert(label);
                        continue;
                    }

                    if(!labelHasSequential(backState, kill, label)) {
                        if(toCondense.insert(label).second) {
                            missing = subtractLabel(backState, label, missing);
                        }
                    }

/*                    uint64_t first = getFirstLabel(backState, label);
                    uint64_t last = getLastLabel(backState, label);

                    uint64_t notPresent = subtractLabel(backState, label, kill);

                    //get rid of sequential instructions
                    if(hasLabelInRange(backState, notPresent, first, last)) {
                        toCondense.insert(label);
                    }
                    else {
                        toCondense.insert(kill);
                    }*/

                    //if includes last label, set to all kill labels (approximates checking if all labels above the smallest are included and setting to max labels)
                    /*if(labelIsSubsetOf(backState, last, label)) {
                        toCondense.insert(kill);
                    }
                    else {
                        toCondense.insert(label);
                    }*/
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


            unordered_map<uint64_t, uint64_t> insMap;
            size = getNewLabel(backState);
            for(uint64_t i = 1; i < size; i++) {
                if(condensed[i]) {
                    if(cfg != NULL) {
                        fprintf(cfg, "  B%llu [shape=box, style=solid, label=\"%llu\"];\n", (unsigned long long) i, (unsigned long long) i);
                    }
                    uint64_t group = i;
                    while(group != 0) {
                        insMap[popLabel(backState, &group)] = i;
                    }
                    
                }
            }
            delete[] condensed;


            unordered_map< pair<uint64_t, uint64_t> , uint32_t, pairHash> controlFlow;
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
                    fprintf(cfg, "  B%llu -> B%llu [style=solid, color=\"black\", label=\"%u\"];\n", (unsigned long long) it->first.first, (unsigned long long) it->first.second, it->second);
                }
            }


            dumps.pop_back();
            if(dumps.empty()) {
                if(cfg != NULL) {
                    fprintf(cfg, "}\n");
                    fclose(cfg);
                }
                exit(0);
            }

            printf("\n/////////////////////////\n\n");
        }

        freeInsInfo(info);
        delete info;
    } 

    freeTaint(backState);
    closeReader(readerState);

    return 0;
}
