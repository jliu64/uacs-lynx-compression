
/* File: BlockQueue.h
 * Author: Theodore Sackos
 * Purpose: This header file defines the prototypes and structures
 * used to represent and operate on a BlockQueue.
 */
#include "../../cfg/cfg.h"
#include <assert.h>

#ifndef BLOCKQUEUE_H_
#define BLOCKQUEUE_H_

/* Each BlockQueue node has a pointer to the next
 * block queue node and a pointer to the block
 * being represented by this node. */
typedef struct q{
    Bbl *block;
    struct q *next;
} Queue;

/* Queue *initQ(Queue **next) -- next is a pointer to the
 * dummy node in front of the next element to be removed 
 * (dequeued), last is a pointer to the dummy node behind
 * the last element in the queue. 
 *
 * | last |                           | next | <--_
 *    |                                   |        |
 *    v                                   v        |
 *  | N | -> |N-1| -> |N-2| -> ... -> |First in| ->'
 * 
 * Notes for use:
 * 1) Use initQ as follows:
 *       Queue *next, *last;
 *       next = initQ(&last);
 * 2) Do not expect an iterating pointer to reach NULL - iterate until
 *    this pointer == tail.
 * 3) Users are responsible to keeping track of the size of the queue!
 */
Queue *initQ  (Queue **terminator);

/* enqueue (Bbl *block, Queue *last, Queue *next) --
 * Insert block in the back of the line surrounded by
 * last and next 
 */
void enqueue  (Bbl *block, Queue *last, Queue *next);

/* Bbl *dequeue(Queue *last, Queue *next) -- Remove
 * the element from the front of the queue surrouned by
 * last and first and return the block that it stores 
 */
Bbl *dequeue  (Queue *last, Queue *next);

/* char Qcontains(Bbl *check, Queue *last, Queue *next) --
 * returns 1 if the queue surrounded by last and next contains
 * a Queue node representing the Basic Block check. Otherwise
 * returns 0.
 */
char Qcontains(Bbl *check, Queue *last, Queue *next);

#endif
