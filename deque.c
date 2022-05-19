#include <stdlib.h>
#include <string.h>
#include "deque.h"
#include "logger.h"

#define MAX_DEQUE_CAPACITY (1 << 20)

pDeque new_deque(pDequeType type){
    pDeque deque = NULL;
    if ((deque = (pDeque)malloc(sizeof(Deque))) == NULL){
        logwarn("Out of memory when create new deque");
        return NULL;
    }
    deque->head = NULL;
    deque->tail = NULL;
    deque->count = 0;
    deque->type = type;
    return deque;
}

void dealloc_deque(pDeque deque){
    pDequeEntry entry, next;

    if (deque == NULL)
        return;
    entry = deque->head;
    do {
        dequeFreeEntry(deque, entry->val);
        next = entry->next;
        free(entry);
        entry = next;
    } while (entry && entry != deque->head);
    
    free(deque);
    return;
}

int deque_append(pDeque deque, void* val){
    pDequeEntry entry = NULL;
    if (( entry = (pDequeEntry)malloc(sizeof(DequeEntry)) ) == NULL){
        logwarn("Out of memory when create new deque entry");
        return 0;
    }
    memset(entry, 0, sizeof(DequeEntry));

    if (deque->head == NULL){
        deque->head = entry;
        deque->tail = entry;
    }
    entry->val = val;
    entry->next = deque->head;
    entry->prev = deque->tail;
    deque->head->prev = entry;
    deque->tail->next = entry;

    deque->count++;
    deque->tail = entry;
    return 1;
}

int deque_appendleft(pDeque deque, void* val){
    pDequeEntry entry = NULL;
    if ((entry = (pDequeEntry)malloc(sizeof(DequeEntry))) == NULL){
        logwarn("Out of memory when create new deque entry");
        return 0;
    }
    memset(entry, 0, sizeof(DequeEntry));

    if (deque->head == NULL){
        deque->head = entry;
        deque->tail = entry;
    }
    entry->val = val;
    entry->next = deque->head;
    entry->prev = deque->tail;
    deque->head->prev = entry;
    deque->tail->next = entry;

    deque->count++;
    deque->head = entry;
    return 1;
}

pDequeEntry deque_pop(pDeque deque){
    pDequeEntry res = NULL, head;
    if (deque->count == 0)
        return NULL;
    res = deque->head;
    head = deque->head;

    deque->head = head->next;
    deque->head->prev = deque->tail;
    deque->tail->next = deque->head;

    deque->count--;
    res->prev = NULL;
    res->next = NULL;
    if(deque->count==0){
        deque->head = NULL;
        deque->tail = NULL;
    }
    return res;
}

pDequeEntry deque_popleft(pDeque deque){
    pDequeEntry res = NULL, tail;
    if (deque->count == 0)
        return NULL;

    res = deque->tail;
    tail = deque->tail;

    deque->tail = tail->prev;
    deque->tail->next = deque->head;
    deque->head->prev = deque->tail;

    deque->count--;
    res->prev = NULL;
    res->next = NULL;
    if(deque->count==0){
        deque->head = NULL;
        deque->tail = NULL;
    }
    return res;
}

size_t deque_size(pDeque deque){
    return deque->count;
}

void deque_iter(pDeque deque, void(*cb)(DequeVal val)){
    pDequeEntry current;
    DequeVal val;
    if (deque == NULL)
        return;
    current = deque->head;

    do{
        val = current->val;
        cb(val);
        current = current->next;
    } while (current != deque->head);

}

// 交换e1 和 e2 的位置, 返回0表示交换失败, 1表示交换成功
int deque_swap(pDeque deque, pDequeEntry e1, pDequeEntry e2){
    DequeEntry te1 = {0};
    if(e1 == NULL || e2 == NULL)
        return 0;
    te1.next = e1->next;
    te1.prev = e1->prev;
    //te1.val = e1->val;

    //e1->val = e2->val;
    e1->prev->next = e2;
    e1->next->prev = e2;

    //e2->val = te1.val;
    e2->prev->next = e1;
    e2->next->prev = e1;

    e1->prev = e2->prev;
    e1->next = e2->next;

    e2->next = te1.next;
    e2->prev = te1.prev;

    return 1;
}

int deque_move_head(pDeque deque, pDequeEntry entry){
    DequeEntry te = {0};
    if(deque == NULL || entry == NULL)
        return 0;
    if(deque->count <= 1 || deque->head == entry)
        return 1;
    if(deque->tail == entry){
        deque->head = entry;
        deque->tail = entry->prev;
        return 1;
    }

    // 把entry从原来的位置移除
    entry->prev->next = entry->next;
    entry->next->prev = entry->prev;

    entry->next = deque->head;
    entry->prev = deque->tail;
    
    deque->head->prev = entry;
    deque->tail->next = entry;

    deque->head = entry;
    deque->tail = entry->prev;
    return 1;
}

#ifdef TEST_DEQUE

static DequeType dtype = {
    NULL,
    NULL
};

static void cb(void* val){
    logdebug("val in deque is %d", val);
}

#define COUNT_OF_VALS 9

static void test(){
    int vals[COUNT_OF_VALS] = { 22, 1, 5, 0, -1, 7, 999, 87, 2 };
    pDeque deque = new_deque(&dtype);
    pDequeEntry entry = NULL;
    for (int i = 0; i < COUNT_OF_VALS; i++){
        deque_appendleft(deque, vals[i]);
    }
    deque_iter(deque, cb);

    for (int i = 0; i < COUNT_OF_VALS; i++){
        entry = deque_pop(deque);
        logdebug("pop %d from deque", entry->val);
    }
    dealloc_deque(deque);
}

int main(){
    test();
}

#endif // TEST_DEQUE

