/* Author: Theodore Sackos
 * Purpose: This structure defines a Queue<Block *> with a linked list
 * implementation. See initQ documentation for notes on use. 
 */

#include "BlockQueue.h"

Queue *initQ(Queue **terminator){
    Queue *starter = (Queue *) malloc(sizeof(Queue));
    if(starter == NULL){
        fprintf(stderr, "Malloc Failed (initQ() - creating last wall)\n");
        exit(1);
    }
    starter->block = NULL;
    
    *terminator = (Queue *) malloc(sizeof(Queue));
    if(*terminator == NULL){
        fprintf(stderr, "Malloc Failed (initQ() - creating next wall)\n");
        exit(1);
    }
    (*terminator)->block = NULL;

    starter->next = *terminator;
    (*terminator)->next = starter;

    return starter;
}

void enqueue(Bbl *block, Queue *last, Queue *next){
    
    /* Allocate for a new Queue node and initialize its values */
    Queue *enQ = (Queue *) malloc(sizeof(Queue));
    if(enQ == NULL){
        fprintf(stderr, "Malloc Failed (enqueue())\n");
        exit(1);
    }
    enQ->block = block;
    enQ->next = last->next;

    /* If queue is of size 0, set dummy node's next pointer to 
     * the final (only) element */
    if(last->next == next)
        next->next = enQ;

    /* Insert */
    last->next = enQ;
}

Bbl *dequeue(Queue *last, Queue *next){
    /* If Queue is empty report nonfatal error */
    if(last-> next == next){
        printf("Attempting to dequeue empty queue\n");
        return NULL;
    }

    Queue *temp;
    for(temp = last; temp->next != next->next; temp = temp->next)
        /* NOP */;
    /* temp is now the 2nd to last element */
    assert(temp->next->next == next);
    
    Bbl *deQ = next->next->block; 
    temp->next = next;
    free(next->next);
    next->next = temp;
    return deQ;
}

char Qcontains(Bbl *check, Queue *last, Queue *next){
    Queue *temp;
    for(temp = last->next; temp != next; temp = temp->next)
        if(temp->block == check)
            return 1;

    return 0;
}

void Qclean(Queue *last, Queue *next){
    Queue *temp = NULL;
    for(temp = last->next; temp != next; temp = last->next){
        last->next = temp->next;
        free(temp);
    }
    next->next = last;
}

void Qdestroy(Queue *last, Queue *next){
    Qclean(last, next);
    free(last);
    free(next);
}
