#include <assert.h>
#include "dict.h"
#include "logger.h"
#include "globals.h"

pKey dummyKey = (pKey)"<dummy>";

#ifdef WIN32
__declspec(thread) char nowbuf[TIME_BUF_SIZE] = { '\0' };
#else
__thread char nowbuf[TIME_BUF_SIZE] = { '\0' };
#endif // WIN32

pDict new_dict(size_t size, pDictType type) {
	pDict dict = NULL;
	pDictEntry table;
	size_t i = 0;
	if (size > MAX_DICT_SIZE || 
		(dict = (pDict)malloc(sizeof(Dict))) == NULL ||
		(table = (pDictEntry)malloc(sizeof(DictEntry)* size)) == NULL) {

		logwarn("Out of memory when create tale with size %lu", size);
		if (dict)
			free(dict);
		return NULL;
	}
	
	memset(table, 0, size * sizeof(DictEntry));

	dict->type = type;
	dict->mask = size - 1;
	dict->fill = 0;
	dict->active = 0;
	dict->table = table;
	return dict;
}

void* dealloc_dict(pDict dict) {
	pDictEntry entry;
	size_t i = 0;
	if (dict == NULL)
		return NULL;

	i = dict->fill;

	for (entry = dict->table; i > 0; entry++) {
		if (entry->val != NULL){		//active slot
			--i;
			dictFreeKey(dict, entry, entry->key);
			dictFreeVal(dict, entry);
		}
		else if (entry->key == dummyKey){	// dummy slot
			--i;
		}
		/*else no thing to do*/				//empty slot
	}
	free(dict->table);
	free(dict);
	return NULL;
}

static pDictEntry lookup(pDict dict, pKey key, long hashval) {
	
	size_t i = hashval & dict->mask, perturb;
	pDictEntry ep = &(dict->table[i]), freeslot;
	if (ep->key == NULL || ep->key == key) {
		return ep;
	}
	if (ep->key == dummyKey) {
		freeslot = ep;
	}
	else {
		if (ep->hash == hashval && dictKeyCmp(dict, ep->key, key) )
			return ep;
		freeslot = NULL;
	}

	for (perturb = hashval;; perturb >>= PERTURB_SHIFT) {
		i = (i << 2) + i + perturb + 1;
		ep = &(dict->table[i & DICT_MASK(dict)]);
		if (ep->key == NULL) {
			return freeslot == NULL ? ep : freeslot;
		}
		if (
			ep->key == key || (
			ep->hash == hashval && ep->key != dummyKey && dictKeyCmp(dict, ep->key, key)
			)) {
			return ep;
		}
		if (ep->key == dummyKey && freeslot == NULL) {
			freeslot = ep;
		}
	}
	logerror("impossible!");
	return NULL;
}

static int dictresize(pDict dict, size_t size){

	assert(dict != NULL);

	size_t newsize = MIN_DICT_SIZE, i = dict->fill;
	pDictEntry newtable = NULL, oldtable = dict->table, ep, entry;

	for (; newsize <= size && newsize > 0; newsize <<= 1);

	if (newsize < 0 
		|| newsize > MAX_DICT_SIZE 
		|| (newtable = (pDictEntry)malloc(sizeof(DictEntry) * newsize)) == NULL){

		logwarn("Out of memory when resize dict to %lu", newsize);
		return -1;
	}
	memset(newtable, 0, sizeof(DictEntry)* newsize);

	dict->table = newtable;
	dict->fill = 0;
	dict->active = 0;
	dict->mask = newsize - 1;

	for (ep = oldtable; i > 0; ep++){
		if (ep->val != NULL){
			--i;
			entry = lookup(dict, ep->key, ep->hash);		// 肯定是空槽
			entry->key = ep->key;
			entry->val = ep->val;				// 这里不会申请内存, 因为在插入到oldtable时, 已经申请过了
			dict->active++;
			dict->fill++;
		}
		else if (ep->key == dummyKey){
			--i;
		}
	}
	free(oldtable);
	return 1;
}

pDictEntry get_item(pDict dict, pKey key) {
	long hashval = dict->type->hash(key);
	pDictEntry res = lookup(dict, key, hashval);
	return res;
}

int set_item(pDict dict, pKey key, pValue val) {
	long hashval = dict->type->hash(key);
	pDictEntry res = lookup(dict, key, hashval);
	int need_resize = res->key == NULL ? 1 : 0;
	int resize_flag = 1;
	if (res->key == NULL){
		dict->active++;
		dict->fill++;
		dictSetKey(dict, res, key);
	}
	else if (res->key == dummyKey){
		dict->active++;
		dictSetKey(dict, res, key);
	}
	else{
		dictFreeVal(dict, res);
	}
	dictSetVal(dict, res, val);
	res->hash = hashval;

	if (EXCEED_LOAD_RATE(dict) && need_resize){
		resize_flag = dictresize(dict, DICT_NEW_SIZE(dict));
	}
	return resize_flag;

}

int del_item(pDict dict, pKey key) {
	long hashval = dict->type->hash(key);
	pDictEntry entry = lookup(dict, key, hashval);
	int resize_flag = 1;
	if (entry->key != NULL && entry->key != dummyKey){	// 如果key对应着有效的entry, 则active要-1
		dictFreeKey(dict, entry, key);
		dictFreeVal(dict, entry);
		entry->key = dummyKey;
		entry->val = NULL;	
		entry->hash = -1;
		dict->active--;
		if (EXCEED_LOAD_RATE(dict)){
			resize_flag = dictresize(dict, DICT_NEW_SIZE(dict));
		}
	}
	return resize_flag;
}

long hash(pKey key) {
	if (key == NULL) {
		return 0;
	}
	size_t len = strlen(key);
	if (len == 0)
		return 0;
	unsigned char* p = (unsigned char*)key;
	long x = 0;
	x ^= *p << 7;
	for (size_t i = 0; i < len; i++)
	{
		x = (1000003 * x) ^ *p++;
	}
	x ^= len;
	x ^= 0;
	if (x == -1) {
		x = -2;
	}
	return x;
}


//#define TEST_HASHTABLE

#ifdef TEST_HASHTABLE

#define sz 8

static int streq(pKey k1, pKey k2){
	return strcmp(k1, k2) == 0 ? 1 : 0;
}

static DictType testType = {
	hash,
	NULL,
	NULL,
	streq,
	NULL,
	NULL
};




int main() {
	
	char *keys[sz] = { "zhao", "qian", "sun", "li", "zhou", "wu", "zheng", "wang"};
	char *vals[sz] = { "1", "2", "3", "4", "5", "6", "7", "8" };

	pDict dict = new_dict(4, &testType);
	
	for (int i = 0; i < sz; i++) {
		char* key = keys[i];
		char* val = vals[i];
		set_item(dict, key, val);
	}
	for (int i = 0; i < sz; i++) {
		pDictEntry entry = get_item(dict, keys[i]);
		del_item(dict, entry->key);
		logdebug("%s", (char*)(entry->val));
	}

	return 0;
}


#endif // TEST_HASHTABLE
