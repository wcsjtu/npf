#ifndef _DICT_H
#define _DICT_H

#include <string.h>

typedef void* pValue;
typedef void* pKey;

typedef struct _entry{
    pKey key;
    long hash;
    pValue val;
} DictEntry, *pDictEntry;


typedef struct _DictType{
    long(*hash)(void* key);
    void* (*keyDup)(void* key);
    void* (*valDup)(void* val);
    int(*keyEq)(void *key1, void *key2);
    void(*keyFree)(pDictEntry entry, void* key);
    void(*valFree)(void* val);
}DictType, *pDictType;



typedef struct _dict{
    size_t fill;
    size_t mask;
    size_t active;
    pDictType type;
    pDictEntry table;
} Dict, *pDict;


#define MAX_DICT_SIZE (1 << 24)
#define MIN_DICT_SIZE 8
#define PERTURB_SHIFT 5
#define MAX_HASH_LOADING_RATE 0.75

#define DICT_MASK(d) (d->mask)
#define DICT_SIZE(d) (d->mask+1)
#define DICT_TABLE(d) (d->table)
#define MALLOC_DICT(size) ( (pDict)malloc(sizeof(Dict) + size * sizeof(pDictEntry)) )

#define DICT_NEW_SIZE(d)	( (d->active > 50000 ? 2 : 4) * d->active )
#define EXCEED_LOAD_RATE(d)	( d->fill * 4 >= (d->mask+1) * 3 )
//#define EXCEED_LOAD_RATE(d) 0


#define dictFreeKey(d, entry, key) do { \
    if((d)->type->keyFree)  \
        (d)->type->keyFree(entry, key); \
} while (0)

#define dictFreeVal(d, entry) do {\
    if ((d)->type->valFree)\
        (d)->type->valFree((entry)->val);\
} while (0);


#define dictSetKey(d, entry, key) do{\
    if((d)->type->keyDup){\
        entry->key= (d)->type->keyDup(key);\
    } else{\
        entry->key = (key);\
    }\
    entry->hash=(d)->type->hash(entry->key);\
}while (0)

#define dictSetVal(d, entry, val) do{\
    if ((d)->type->valDup) \
        entry->val = (d)->type->valDup(val);\
    else\
        entry->val = (val);\
}while (0)

#define dictKeyCmp(d, key1, key2) ( (d)->type->keyEq ? (d)->type->keyEq(key1, key2) : (key1)==(key2) )

pKey dummyKey;


pDict new_dict(size_t size, pDictType type);
void* dealloc_dict(pDict dict);
pDictEntry get_item(pDict dict, pKey key);
int set_item(pDict dict, pKey key, pValue val);
int del_item(pDict dict, pKey key);

long hash(pKey key);

#endif // !_HASH_TABLE_H

#pragma once
