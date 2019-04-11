#ifndef _DEQUE_H
#define _DEQUE_H

typedef void* DequeVal;

typedef struct _dequetype{
	void*(*dequeValDup)(void* val);
	void(*dequeValFree)(void* val);
} DequeType, *pDequeType ;

typedef struct _deqentry{
	void* val;
	struct _deqentry* prev;
	struct _deqentry* next;
} DequeEntry, *pDequeEntry;

typedef struct _deque{
	pDequeType type;
	pDequeEntry head;
	pDequeEntry tail;
	size_t count;
}Deque, *pDeque;

pDeque new_deque(pDequeType type);

void dealloc_deque(pDeque deque);

int deque_append(pDeque deque, void* val);

int deque_appendleft(pDeque deque, void* val);

pDequeEntry deque_pop(pDeque deque);

pDequeEntry deque_popleft(pDeque deque);

size_t deque_size(pDeque deque);

#define dequeFreeEntry(deque, val)  do {\
	if(deque->type->dequeValFree)\
		deque->type->dequeValFree(val);\
} while(0)

#endif
