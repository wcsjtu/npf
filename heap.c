#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "heap.h"
#include "logger.h"

static int heap_shrink(pHeap heap){
	if (NEED_SHRINK_HEAP(heap)){
		size_t newcap = heap->capacity - (heap->capacity >> 2);	// 3/4
		pHeapEntry buf = (pHeapEntry)realloc(heap->buf, newcap * sizeof(HeapEntry));
		if (buf == NULL)
			return 0;
		heap->capacity = newcap;
		heap->buf = buf;
	}
	return 1;
}

static int heap_scale(pHeap heap){
	size_t new_allocated = (heap->capacity >> 3) + (heap->capacity < 9 ? 3 : 6);
	size_t newcap = heap->capacity + new_allocated;
	pHeapEntry buf = NULL;
	if (newcap > MAX_HEAP_SIZE
		|| (buf = (pHeapEntry)realloc(heap->buf, newcap * sizeof(HeapEntry))) == NULL){
		logwarn("Out of memory when scale heap to %lu", newcap);
		return 0;
	}
	memset(buf + heap->capacity, 0, sizeof(HeapEntry)* new_allocated);
	heap->buf = buf;
	heap->capacity = newcap;
	return 1;
}

pHeap new_heap(size_t capacity, pHeapType type){
	pHeap heap = NULL;
	void* buf;
	if (capacity >= MAX_HEAP_SIZE
		|| (heap = malloc(sizeof(Heap))) == NULL
		|| (buf = malloc(sizeof(HeapEntry)* capacity)) == NULL){
		logwarn("Out of memory when create new heap with size %lu", capacity);
		if (heap)
			free(heap);
		return NULL;
	}
	memset(buf, 0, sizeof(HeapEntry)* capacity);
	heap->capacity = capacity;
	heap->used = 0;
	heap->type = type;
	heap->buf = buf;
	return heap;
}

void dealloc_heap(pHeap heap){
	HeapEntry entry;
	if (heap == NULL)
		return;
	for (size_t i = 0; i < heap->used; i++){
		entry = heap->buf[i];
		heapFreeEntry(heap, entry);
	}
	free(heap->buf);
	free(heap);
	return;
}

int heap_push(pHeap heap, HeapEntry entry){

	size_t used = heap->used, pos = heap->used, parent = 0;

	if (heap->used >= heap->capacity && !heap_scale(heap)){
		logwarn("failed to push item to heap!");
		return 0;
	}
	heap->buf[used] = entry;
	while (pos > 0)
	{
		parent = (pos - 1) >> 1;
		if (heapEntryCmp(heap, pos, parent) >= 0)
			break;
		swapHeapEntry(heap, pos, parent);
		pos = parent;
	}
	heap->used++;
	return 1;
}

HeapEntry heap_pop(pHeap heap){
	size_t used, pos = 0, childpos, bro;
	if (heap == NULL || heap->used <= 0){
		logwarn("Pop from an empty heap");
		return NULL;
	}
	HeapEntry res = heap->buf[0];
	heap->used--;
	used = heap->used;

	if (!used)
		return res;

	heap->buf[0] = heap->buf[used];

	while (pos < used){
		childpos = 2 * pos + 1;
		if (childpos >= used)
			break;
		bro = childpos + 1;
		if (bro < used && heapEntryCmp(heap, childpos, bro) > 0)
			childpos = bro;
		if (heapEntryCmp(heap, pos, childpos) <= 0)
			break;
		swapHeapEntry(heap, pos, childpos);
		pos = childpos;
	}
	heap_shrink(heap);
	return res;
}

size_t heapify(pHeap heap){
	size_t used = heap->used;
	heap->used = 0;
	HeapEntry entry;

	for (size_t i = 0; i < used; i++){
		entry = heap->buf[i];
		if (invalidHeapEntry(heap, entry))
			continue;		// Å×ÆúÎÞÐ§µÄentry
		heap_push(heap, entry);
	}
	heap_shrink(heap);
	return heap->used;
}


#ifdef TEST_HEAP

typedef struct _Timer{
	long due;
	void(*callback)(int fd, int events);
}Timer, *pTimer;

int timer_compare(HeapEntry t, HeapEntry t1){
	if (((pTimer)t)->due > ((pTimer)t1)->due)
		return 1;
	if (((pTimer)t)->due == ((pTimer)t1)->due)
		return 0;
	else
		return -1;
}

void timer_free(void* t){
	if (t)
		free(t);
}

void* timer_dup(void* t){
	pTimer res = (pTimer)malloc(sizeof(Timer));
	if (res == NULL){
		logwarn("Out of memory when create new timer");
		return NULL;
	}
	res->due = ((pTimer)t)->due;
	res->callback = ((pTimer)t)->callback;
	return res;
}

int timer_valid(void* t){
	return ((pTimer)t)->callback != NULL;
}

void cancel_timer(pTimer t){
	if (t)
		t->callback = NULL;
}

void showfd(int fd, int events){
	logdebug("TIMER CALLBACK: fd == %d", fd);
	return;
}


static HeapType timerType = {
	timer_compare,
	timer_free,
	timer_dup,
	timer_valid
};

#define TIMER_COUNT 811

static pTimer new_timer(){
	int due = rand();
	pTimer t = (pTimer)malloc(sizeof(Timer));
	t->callback = showfd;
	t->due = due;
	return t;
}

static int test_push_pop(){
	pHeap heap = new_heap(TIMER_COUNT >> 3, &timerType);
	pTimer timer;
	if (heap == NULL)
		return 0;

	for (int i = 0; i < TIMER_COUNT; i++){
		timer = new_timer();
		assert(timer);
		heap_push(heap, timer);
	}
	for (int i = 0; i < TIMER_COUNT; i++){
		timer = heap_pop(heap);
		logdebug("timer->due = %lu", timer->due);
	}
	dealloc_heap(heap);
	return 0;
}

static int test_heapify(){
	pHeap heap = new_heap(TIMER_COUNT >> 3, &timerType);
	pTimer timer;
	int j = 0, tmp=0;
	size_t c = 0;
	if (heap == NULL)
		return 0;

	for (int i = 0; i < TIMER_COUNT; i++){
		timer = new_timer();
		assert(timer);
		heap_push(heap, timer);
	}

	for (int i = 0; i < (TIMER_COUNT >> 2); i++){
		tmp = rand();
		j = tmp & TIMER_COUNT;
		cancel_timer(heap->buf[j]);
	}
	c = heapify(heap);
	for (int i = 0; i < heap->used; i++){
		timer = heap_pop(heap);
		logdebug("timer->due = %lu", timer->due);
		timer_free(timer);
	}

	logdebug("after heapify, used of heap == %ld", c);
	dealloc_heap(heap);
	return 1;
}


int main(){

	test_heapify();
}

#endif