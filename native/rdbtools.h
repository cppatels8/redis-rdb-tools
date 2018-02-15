#ifndef __RDBTOOLS_H
#define __RDBTOOLS_H

#include <stdio.h>
#include "sds.h"

/* The current RDB version. When the format changes in a way that is no longer
 * backward compatible this number gets incremented. */
#define RDB_VERSION 8

/* Defines related to the dump file format. To store 32 bits lengths for short
 * keys requires a lot of space, so we check the most significant 2 bits of
 * the first byte to interpreter the length:
 *
 * 00|XXXXXX => if the two MSB are 00 the len is the 6 bits of this byte
 * 01|XXXXXX XXXXXXXX =>  01, the len is 14 byes, 6 bits + 8 bits of next byte
 * 10|000000 [32 bit integer] => A full 32 bit len in net byte order will follow
 * 10|000001 [64 bit integer] => A full 64 bit len in net byte order will follow
 * 11|OBKIND this means: specially encoded object will follow. The six bits
 *           number specify the kind of object that follows.
 *           See the RDB_ENC_* defines.
 *
 * Lengths up to 63 are stored using a single byte, most DB keys, and may
 * values, will fit inside. */
#define RDB_6BITLEN 0
#define RDB_14BITLEN 1
#define RDB_32BITLEN 0x80
#define RDB_64BITLEN 0x81
#define RDB_ENCVAL 3
#define RDB_LENERR UINT64_MAX

/* When a length of a string object stored on disk has the first two bits
 * set, the remaining six bits specify a special encoding for the object
 * accordingly to the following defines: */
#define RDB_ENC_INT8 0        /* 8 bit signed integer */
#define RDB_ENC_INT16 1       /* 16 bit signed integer */
#define RDB_ENC_INT32 2       /* 32 bit signed integer */
#define RDB_ENC_LZF 3         /* string compressed with FASTLZ */

/* Map object types to RDB object types. Macros starting with OBJ_ are for
 * memory storage and may change. Instead RDB types must be fixed because
 * we store them on disk. */
#define RDB_TYPE_STRING 0
#define RDB_TYPE_LIST   1
#define RDB_TYPE_SET    2
#define RDB_TYPE_ZSET   3
#define RDB_TYPE_HASH   4
#define RDB_TYPE_ZSET_2 5 /* ZSET version 2 with doubles stored in binary. */
#define RDB_TYPE_MODULE 6
#define RDB_TYPE_MODULE_2 7 /* Module value with annotations for parsing without
                               the generating module being loaded. */
/* NOTE: WHEN ADDING NEW RDB TYPE, UPDATE rdbIsObjectType() BELOW */

/* NOTE: WHEN ADDING NEW NATIVE DATA TYPE, UPDATE BELOW */
#define NUMBER_OF_NATIVE_DATATYPE 5
const char *NATIVEDATATYPES[NUMBER_OF_NATIVE_DATATYPE] = {"string", "list", "set", "zset", "hash"};

/* Object types for encoded objects. */
#define RDB_TYPE_HASH_ZIPMAP    9
#define RDB_TYPE_LIST_ZIPLIST  10
#define RDB_TYPE_SET_INTSET    11
#define RDB_TYPE_ZSET_ZIPLIST  12
#define RDB_TYPE_HASH_ZIPLIST  13
#define RDB_TYPE_LIST_QUICKLIST 14
#define RDB_TYPE_STREAM_LISTPACKS 15
/* NOTE: WHEN ADDING NEW RDB TYPE, UPDATE rdbIsObjectType() BELOW */

#define NUMBER_OF_ENCODINGS 16
const char *DATATYPES[NUMBER_OF_ENCODINGS] = {"string", "list", "set", "zset", "hash", "zset", "module", "module",
                            NULL, 
                            "hash", "list", "set", "zset", "hash", "list", "stream"};

const char *ENCODINGS[NUMBER_OF_ENCODINGS] = {"string", "linkedlist", "hashtable", "skiplist", "hashtable", "skiplist", "type1", "type2",
                            NULL, 
                            "zipmap", "ziplist", "intset", "ziplist", "ziplist", "quicklist", "listpack"};

/* Test if a type is an object type. */
#define rdbIsObjectType(t) ((t >= 0 && t <= 7) || (t >= 9 && t <= 15))

/* Special RDB opcodes (saved/loaded with rdbSaveType/rdbLoadType). */
#define RDB_OPCODE_AUX        250
#define RDB_OPCODE_RESIZEDB   251
#define RDB_OPCODE_EXPIRETIME_MS 252
#define RDB_OPCODE_EXPIRETIME 253
#define RDB_OPCODE_SELECTDB   254
#define RDB_OPCODE_EOF        255

/* Module serialized values sub opcodes */
#define RDB_MODULE_OPCODE_EOF   0   /* End of module value. */
#define RDB_MODULE_OPCODE_SINT  1   /* Signed integer. */
#define RDB_MODULE_OPCODE_UINT  2   /* Unsigned integer. */
#define RDB_MODULE_OPCODE_FLOAT 3   /* Float. */
#define RDB_MODULE_OPCODE_DOUBLE 4  /* Double. */
#define RDB_MODULE_OPCODE_STRING 5  /* String. */

/* rdbLoad...() functions flags. */
#define RDB_LOAD_NONE   0
#define RDB_LOAD_ENC    (1<<0)
#define RDB_LOAD_PLAIN  (1<<1)
#define RDB_LOAD_SDS    (1<<2)

#define RDB_SAVE_NONE 0
#define RDB_SAVE_AOF_PREAMBLE (1<<0)

#define LONG_STR_SIZE      21          /* Bytes needed for long -> str + '\0' */

#define SIZEOF_LONG 8
#define SIZEOF_POINTER 8
#define ROBJ_OVERHEAD (SIZEOF_POINTER + 1)
#define HASHTABLE_ENTRY_OVERHEAD (2*SIZEOF_POINTER + 8)
#define KEY_EXPIRY_OVERHEAD (HASHTABLE_ENTRY_OVERHEAD + 8)

#define HASHTABLE_OVERHEAD(size) (4 + 7*SIZEOF_LONG + 4*SIZEOF_POINTER + nextPower(size)*SIZEOF_POINTER*1.5)

#define LINKEDLIST_OVERHEAD (SIZEOF_LONG + 5*SIZEOF_POINTER)
#define LINKEDLIST_ITEM_OVERHEAD (3 * SIZEOF_POINTER)

#define QUICKLIST_OVERHEAD (2*SIZEOF_POINTER + SIZEOF_LONG + 2*4)
#define QUICKLIST_ITEM_OVERHEAD (4*SIZEOF_POINTER + SIZEOF_LONG + 2*4)

#define ZSKIPLIST_MAXLEVEL 32
#define ZSKIPLIST_P 0.25
#define SKIPLIST_OVERHEAD(size) (2*SIZEOF_POINTER + HASHTABLE_OVERHEAD(size) + (2*SIZEOF_POINTER + 16))
#define SKIPLIST_ENTRY_OVERHEAD (HASHTABLE_ENTRY_OVERHEAD + 2*SIZEOF_LONG + 8 + (SIZEOF_POINTER + 8) * zsetRandomLevel())
#define TOP_KEYS_COUNT 10

typedef struct MemoryEntry {

    int encdType;
    const char* dataType;
    /*
        Memory used in bytes
    */
    uint64_t bytes;

    char *key;

    /*
        For string, this is the length of the string
        For hash, set, list, sortedset, this is the number of elements
    */
    uint64_t length;
    /*
        For string, this is equal to the length of the string
        For hash, it is the length of the largest key or value in the hash
        For set, it is the length of the largest member in the set
        For list, it is the length of the largest element in the list
        For zset, it is the length of the largest member in the set
    */
    uint64_t lenLargestElement;

    /*
        This is the relative expiry expressed in milliseconds
        The RDB file has the expiry in absolute timestamp. 
        We convert it into a relative timestamp by using 
        the RDB snapshot creation time as the reference timestamp.

        RDB versions >=8 have the snapshot time stored as an auxiliary field.
        However, older versions do not have aux fields, so we have to 
        figure out the snapshot time using some heuristics.

        1. Accept optional input parameter
        1. Use the file creation timestamp
        1. Use the earliest timestamp found in the RDB. 
            It is guaranteed that the snapshot was created before this timestamp,
            so use it in the worst case
    */
    uint64_t expiry;

    /*
    The serialization algorithm used to store values in redis
    Can be UNKNOWN, JSON, XML, JAVA_SERIALIZED_OBJECT, PYTHON_PICKLE_OBJECT,
    PHP_SERIALIZE,
    */
    int serializer;

    /*
    The compression algorithm, if used
    Can be UNKNOWN, GZIP, ZIP, SNAPPY, LZF, etc.
    */
    int compressionAlgorithm;
    
    /*
        This is a rough indicator of how much memory would be saved 
        if client side compression was used before saving values in redis.
        The actual compression algorithm is LZF.    

        For strings, this directly maps to the bytes saved if the value is compressed
        For hashes, we ignore field names, 
            and sum the memory saved if each value would be compressed.

        For sets, we sum the memory saved if each member were to be compressed
        For sortedsets, we sum the memory saved if each member were to be compressed
        Fr lists, we sum the memory saved if each element were to be compressed.
    */
    uint64_t savingsIfCompressed;

    /*
    Older versions of redis used linkedlists, newer versions use quicklist
    linkedlists use a lot more memory than quicklists
    If the user upgrades redis-server, linkedlists are auto-converted to quicklists
    This value tells the user the potential savings that can be achieved 
    before actually upgrading.
    */
    uint64_t savingsIfLinkedlistToQuicklist;

    /*
    Savings if quicklist were compressed to a depth = 1
    */
    uint64_t savingsIfQuicklistIsCompressed;

    /*
    If the data type is hash in hashtable encoding, 
    list in linkedlist encoding, or sorted set in skiplist encoding, 
    this column will store the savings if it 
    were converted to ziplist encoding.
    */
    uint64_t savingsIfZiplist;

    /*
    If the data type is a set in hashtable encoding,
    and the size of the set is within certain bounds,
    and if the hashtable has only integers,
    then it could potentially be converted to an intset (by adjusting set-max-intset-entries)
    In this case, this field will be set to 1, otherwise it will be 0
    */
    uint64_t savingsIfIntset;

    /*
    If the datatype is a hash with few fields (<15), 
    but there are a large number of such hashes, 
    and the field names are relatively static (i.e. each hash the same fields) -
    then you can convert the hash to a list, 
    and maintain a mapping from fieldname to index 
    */
    uint64_t savingsIfHashToList;

    /*
    If the datatype is a hash, and it has field names 
    that are bigger than 12 bytes, how much memory would we save 
    if each field name was made shorter to 5 bytes on average?
    */
    uint64_t savingsIfHashHadSmallFieldNames;
    
} MemoryEntry;

typedef struct DataTypeSummary {
	uint64_t totalMemory;
	uint64_t totalKeys;
} DataTypeSummary;

typedef struct Statistics {
    uint64_t totalMemory;
    uint64_t totalKeys;

    uint64_t memoryByEncoding[NUMBER_OF_ENCODINGS];
    uint64_t countKeysByEncoding[NUMBER_OF_ENCODINGS];

    MemoryEntry topKeysByMemory[TOP_KEYS_COUNT];
    DataTypeSummary dataTypeSummary[NUMBER_OF_NATIVE_DATATYPE];

} Statistics;

int rdbLoadType(FILE *rdb);
time_t rdbLoadTime(FILE *rdb);
uint64_t rdbLoadLen(FILE *rdb, int *isencoded);
int rdbLoadLenByRef(FILE *rdb, int *isencoded, uint64_t *lenptr);
int rdbLoadObjectType(FILE *rdb);
int rdbMemoryAnalysis(char *rdb, char *csv, char *jsonFile);
sds rdbLoadString(FILE *rdb, uint64_t *memory, uint64_t *savingsIfCompressed);
int rdbLoadBinaryDoubleValue(FILE *rdb, double *val);
int rdbLoadBinaryFloatValue(FILE *rdb, float *val);
int rdbMemoryAnalysisInternal(FILE *rdb, FILE *csv, FILE *jsonOut, uint64_t defaultSnapshotTime);

#endif
