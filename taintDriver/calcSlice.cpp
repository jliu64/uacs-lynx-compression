/**
 * This is the driver for the trace2ascii tool. Most of the work is done by the reader. In here, we just get
 * instructions one by one and print out the information to STDOUT. It should be noted that we are currently
 * only printing out an instruction's: address, source name, function name, thread id, bytes and mnemonic.
 **/

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <utility>

using namespace std;

extern "C" {
#include <Reader.h>
#include <Taint.h>
}

int main(int argc, char *argv[]) {
    if(argc < 3) {
        printf("%s <trace> <lineNum>\n", argv[0]);
        return 1;
    }

    char *trace = argv[1];
    uint64_t target = strtoul(argv[2], NULL, 10);

    ReaderState *readerState = initReader(trace, 0);
    TaintState *taintState = initTaint(readerState);

	ReaderEvent curEvent;

    vector< pair<uint64_t, pair<uint32_t, InsInfo *> > > ops;

    InsInfo *taintAt;

    //vector<pair<uint64_t, uint32_t>> memRead;

    uint64_t insNum = 0;
    while(nextEvent(readerState, &curEvent)) {
        insNum++;
        if(curEvent.type == EXCEPTION_EVENT) {
            printf("EXCEPTION %d\n", curEvent.exception.code);
        }
        else if(curEvent.type == INS_EVENT) {
            InsInfo *info = new InsInfo;
            initInsInfo(info);
            fetchInsInfo(readerState, &curEvent.ins, info);
            ops.push_back(make_pair(insNum, make_pair(curEvent.ins.tid, info)));

            if(insNum == target) {
                taintAt = info;
                break;
            }

            /*if(info.insClass == XED_ICLASS_SYSCALL) {
                uint64_t rax = *((uint64_t *) getRegisterVal(readerState, LYNX_RAX, curEvent.ins.tid));

                if(rax == 0) {
                    uint64_t rdx = *((uint64_t *) getRegisterVal(readerState, LYNX_RDX, curEvent.ins.tid));
                    uint64_t rsi = *((uint64_t *) getRegisterVal(readerState, LYNX_RSI, curEvent.ins.tid));
                    //uint64_t *taint = malloc(sizeof(uint64_t) * rdx);
                    memread.push_back(make_pair(rsi, rdx));
                }
            }*/
        }
    }

    uint64_t validLabels = 0;

    while(!ops.empty()) {
        pair<uint64_t, pair<uint32_t, InsInfo *> > curPair = ops.back();
        uint64_t addr = curPair.first;
        uint32_t tid = curPair.second.first;
        InsInfo *info = curPair.second.second;
        ops.pop_back();


        if(info == taintAt) {
            printf("%llu %s\n", (unsigned long long) addr, info->mnemonic);
            uint64_t label = getNewLabel(taintState);
            /*taintOperandList(taintState, info->srcOps, info->srcOpCnt, tid, label);
            taintOperandList(taintState, info->readWriteOps, info->readWriteOpCnt, tid, label);*/

            int i;
            ReaderOp *ops = info->srcOps;
            for(i = 0; i < info->srcOpCnt; i++) {
                if(ops->type == MEM_OP) {
                    if(ops->mem.seg != LYNX_INVALID) {
                        taintReg(taintState, (LynxReg) ops->mem.seg, tid, label);
                    }
                    if(ops->mem.base != LYNX_INVALID && ops->mem.base != LYNX_RIP && ops->mem.base != LYNX_RSP) {
                        taintReg(taintState, (LynxReg) ops->mem.base, tid, label);
                    }
                    if(ops->mem.index != LYNX_INVALID && ops->mem.index != LYNX_RIP && ops->mem.index != LYNX_RSP) {
                        taintReg(taintState, (LynxReg) ops->mem.index, tid, label);
                    }
                }
            }
        }
        else {

            //if(addr == 0x7f2e53962f1b) {
            //    printf("\n");
            //}

            uint64_t taint = propagateBackward(taintState, tid, info);
            taintReg(taintState, LYNX_RSP, tid, 0);
            taintReg(taintState, LYNX_RBP, tid, 0);
            if(taint) {
                printf("%llu %s\n", (unsigned long long) addr, info->mnemonic);
                /*ReaderOp *ops = info->srcOps;
                for(int i = 0; i < info->srcOpCnt; i++) {
                    if(ops->type == MEM_OP) {
                        for(pair<uint64_t, uint32_t> &read : memReads) {
                            if(ops->mem.addr > read.addr && ops->mem.addr < (read.addr + size)) {
                                validLabels = combineLabels(validLabels, taint);
                                break;
                            }
                        }
                    }
                    ops = ops->next;
                }

                ReaderOp *ops = info->readWriteOps;
                for(int i = 0; i < info->readWriteCnt; i++) {
                    if(ops->type == MEM_OP) {
                        for(pair<uint64_t, uint32_t> &read : memReads) {
                            if(ops->mem.addr > read.addr && ops->mem.addr < (read.addr + size)) {
                                validLabels = combineLabels(validLabels, taint);
                                break;
                            }
                        }
                    }
                    ops = ops->next;
                }*/
            }
        }

        freeInsInfo(info);
        delete info;
    } 

    outputTaint(taintState);

    freeTaint(taintState);
	closeReader(readerState);

	return 0;
}
