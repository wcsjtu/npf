#ifndef _HEAP_H
#define _HEAP_H

#include <stddef.h>

typedef void* HeapEntry;
typedef HeapEntry* pHeapEntry;

typedef struct _heaptype{
    int(*ecmp)(HeapEntry e1, HeapEntry e2);
    void(*efree)(void* ep);
    void*(*edup)(void* ep);
    int(*evalid)(void* ep);	// entry是否有效
} HeapType, *pHeapType;

typedef struct _heap{

    pHeapType type;
    size_t capacity;
    size_t used;
    pHeapEntry buf;
}Heap, *pHeap;

#define MAX_HEAP_SIZE 1 << 20
#define MAX_EXTEND_ITEM 512		// 每次扩容的上限
#define NEED_SHRINK_HEAP(heap) ( heap->used <= (heap->capacity >> 1) && heap->capacity >= MAX_EXTEND_ITEM )
#define HEAP_NEW_CAPACITY(heap) ( (heap->capacity >> 3) + heap->capacity < 9 ? 3 : 6)


#define heapFreeEntry(hp, ep) do {\
    if(hp->type->efree && ep)\
        hp->type->efree(ep);\
} while (0)

#define heapEntryCmp(hp, i, j) ( hp->type->ecmp( hp->buf[i], hp->buf[j]) )

#define swapHeapEntry(hp, i, j) do {\
    HeapEntry tmp = hp->buf[i];\
    hp->buf[i] = hp->buf[j];\
    hp->buf[j] = tmp;\
} while (0)

#define invalidHeapEntry(heap, entry) ( heap->type->evalid && !heap->type->evalid(entry) )

pHeap new_heap(size_t capacity, pHeapType type);
void dealloc_heap(pHeap heap);
int heap_push(pHeap heap, HeapEntry entry);
HeapEntry heap_pop(pHeap heap);
size_t heapify(pHeap heap);


#endif
