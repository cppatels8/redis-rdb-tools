#include "lzf.h"
#include "rdbtools.h"
#include "util.h"
#include "zmalloc.h"

#include <inttypes.h>
#include <string.h> 
#include <math.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>
#include <stdarg.h> /* for va_list */
#include <stdio.h>
#include <stdlib.h>

#define rdbExitReportCorruptRDB(...) rdbCheckThenExit(__LINE__,__VA_ARGS__)

void rdbCheckThenExit(int linenum, char *reason, ...) {
    va_list ap;
    char msg[1024];
    int len;

    len = snprintf(msg,sizeof(msg),
        "Internal error in RDB reading function at rdb.c:%d -> ", linenum);
    va_start(ap,reason);
    vsnprintf(msg+len,sizeof(msg)-len,reason,ap);
    va_end(ap);
    exit(1);
}

/* Load a "type" in RDB format, that is a one byte unsigned integer.
 * This function is not only used to load object types, but also special
 * "types" like the end-of-file type, the EXPIRE type, and so forth. */
int rdbLoadType(FILE *rdb) {
    unsigned char type;
    if (fread(&type, 1, 1, rdb) == 0) return -1;
    return type;
}

time_t rdbLoadTime(FILE *rdb) {
    int32_t t32;
    if (fread(&t32,4, 1, rdb) == 0) return -1;
    return (time_t)t32;
}

uint64_t rdbLoadMillisecondTime(FILE *rdb) {
    int64_t t64;
    if (fread(&t64, 8, 1, rdb) == 0) return -1;
    return (uint64_t)t64;
}

/* Load an encoded length. If the loaded length is a normal length as stored
 * with rdbSaveLen(), the read length is set to '*lenptr'. If instead the
 * loaded length describes a special encoding that follows, then '*isencoded'
 * is set to 1 and the encoding format is stored at '*lenptr'.
 *
 * See the RDB_ENC_* definitions in rdb.h for more information on special
 * encodings.
 *
 * The function returns -1 on error, 0 on success. */
int rdbLoadLenByRef(FILE *rdb, int *isencoded, uint64_t *lenptr) {
    unsigned char buf[2];
    int type;

    if (isencoded) *isencoded = 0;
    if (fread(buf,1, 1, rdb) == 0) return -1;
    type = (buf[0]&0xC0)>>6;
    if (type == RDB_ENCVAL) {
        /* Read a 6 bit encoding type. */
        if (isencoded) *isencoded = 1;
        *lenptr = buf[0]&0x3F;
    } else if (type == RDB_6BITLEN) {
        /* Read a 6 bit len. */
        *lenptr = buf[0]&0x3F;
    } else if (type == RDB_14BITLEN) {
        /* Read a 14 bit len. */
        if (fread(buf+1, 1, 1, rdb) == 0) return -1;
        *lenptr = ((buf[0]&0x3F)<<8)|buf[1];
    } else if (buf[0] == RDB_32BITLEN) {
        /* Read a 32 bit len. */
        uint32_t len;
        if (fread(&len,4, 1, rdb) == 0) return -1;
        *lenptr = ntohl(len);
    } else if (buf[0] == RDB_64BITLEN) {
        /* Read a 64 bit len. */
        uint64_t len;
        if (fread(&len,8, 1, rdb) == 0) return -1;
        /*TODO: Fix endianess over here */
        // *lenptr = ntohu64(len);
        *lenptr = len;
    } else {
        rdbExitReportCorruptRDB(
            "Unknown length encoding %d in rdbLoadLen()",type);
        return -1; /* Never reached. */
    }
    return 0;
}

/* This is like rdbLoadLenByRef() but directly returns the value read
 * from the RDB stream, signaling an error by returning RDB_LENERR
 * (since it is a too large count to be applicable in any Redis data
 * structure). */
uint64_t rdbLoadLen(FILE *rdb, int *isencoded) {
    uint64_t len;

    if (rdbLoadLenByRef(rdb,isencoded,&len) == -1) return RDB_LENERR;
    return len;
}

/* Loads an integer-encoded object with the specified encoding type "enctype".
 * The returned value changes according to the flags, see
 * rdbGenerincLoadStringObject() for more info. */
sds rdbLoadIntegerObject(FILE *rdb, int enctype) {
    
    unsigned char enc[4];
    long long val;

    if (enctype == RDB_ENC_INT8) {
        if (fread(enc,1, 1, rdb) == 0) return NULL;
        val = (signed char)enc[0];
    } else if (enctype == RDB_ENC_INT16) {
        uint16_t v;
        if (fread(enc,2, 1, rdb) == 0) return NULL;
        v = enc[0]|(enc[1]<<8);
        val = (int16_t)v;
    } else if (enctype == RDB_ENC_INT32) {
        uint32_t v;
        if (fread(enc,4, 1, rdb) == 0) return NULL;
        v = enc[0]|(enc[1]<<8)|(enc[2]<<16)|(enc[3]<<24);
        val = (int32_t)v;
    } else {
        val = 0; /* anti-warning */
        rdbExitReportCorruptRDB("Unknown RDB integer encoding type %d",enctype);
    }

    char buf[LONG_STR_SIZE], *p;
    int len = ll2string(buf,sizeof(buf),val);
    p = sdsnewlen(NULL,len);
    memcpy(p,buf,len);
    return p;
}

int rdbSkip(FILE *rdb, off_t size) {
    return fseek(rdb, size, SEEK_CUR);
}

int rdbSkipIntegerObject(FILE *rdb) {
    return rdbSkip(rdb, 4);
}
int rdbSkipLzfStringObject(FILE *rdb) {
    uint64_t len, clen;
    clen = rdbLoadLen(rdb,NULL);
    len = rdbLoadLen(rdb,NULL);
    return rdbSkip(rdb, clen);
}
int rdbSkipStringObject(FILE *rdb) {
    int isencoded;
    uint64_t len;

    len = rdbLoadLen(rdb,&isencoded);
    if (isencoded) {
        switch(len) {
        case RDB_ENC_INT8:
            return rdbSkip(rdb, 1);
        case RDB_ENC_INT16:
            return rdbSkip(rdb, 2);
        case RDB_ENC_INT32:
            return rdbSkip(rdb, 4);
        case RDB_ENC_LZF:
            return rdbSkipLzfStringObject(rdb);
        default:
            rdbExitReportCorruptRDB("Unknown RDB string encoding type %d",len);
        }
    }
    return rdbSkip(rdb, len);
}

/* Load an LZF compressed string in RDB format. The returned value
 * changes according to 'flags'. For more info check the
 * rdbGenericLoadStringObject() function. */
void *rdbLoadLzfStringObject(FILE *rdb, uint64_t *memory, uint64_t *savingsIfCompressed) {
    uint64_t len, clen;
    unsigned char *c = NULL;
    char *val = NULL;

    if ((clen = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return NULL;
    if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return NULL;
    if ((c = zmalloc(clen)) == NULL) goto err;

    val = sdsnewlen(NULL,len);

    /* Load the compressed representation and uncompress it to target. */
    if (fread(c,clen, 1, rdb) == 0) goto err;
    if (lzf_decompress(c,clen,val,len) == 0) goto err;
    zfree(c);
    *savingsIfCompressed = len - clen;
    /*
    TODO refine this heuristic
    */
    *memory =  len + 1 + 16 + 1;
    return val;

err:
    zfree(c);
    zfree(val);
    return NULL;
}

/* Load a SDS string from an RDB file.
 * Also calculates memory in bytes, 
 * and savings if the string were to be stored compressed 
 */
void * rdbLoadStringInternal(FILE *rdb, uint64_t *memory, uint64_t *savingsIfCompressed, int plain) {
    int isencoded;
    uint64_t len;
    
    *savingsIfCompressed = 0;

    len = rdbLoadLen(rdb,&isencoded);
    if (isencoded) {
        switch(len) {
        case RDB_ENC_INT8:
            *memory = 0;
        case RDB_ENC_INT16:
        case RDB_ENC_INT32:
            *memory = 8;
            return rdbLoadIntegerObject(rdb, len);
        case RDB_ENC_LZF:
            return rdbLoadLzfStringObject(rdb, memory, savingsIfCompressed);
        default:
            rdbExitReportCorruptRDB("Unknown RDB string encoding type %d",len);
        }
    }

    void *buf = plain ? zmalloc(len) : sdsnewlen(NULL,len);
    if (len && fread(buf,len, 1, rdb) == 0) {
        if (plain)
            zfree(buf);
        else
            sdsfree(buf);
        return NULL;
    }
    /*
    TODO: refine this metric
    */
    *memory = len + 1 + 16 + 1;
    return buf;
}

char * rdbLoadPlainString(FILE *rdb) {
    uint64_t memory;
    uint64_t savingsIfCompressed;
    return rdbLoadStringInternal(rdb, &memory, &savingsIfCompressed, 1);
}

sds rdbLoadString(FILE *rdb, uint64_t *memory, uint64_t *savingsIfCompressed) {
    return rdbLoadStringInternal(rdb, memory, savingsIfCompressed, 0);
}

/* For information about double serialization check rdbSaveDoubleValue() */
int rdbLoadDoubleValue(FILE *rdb, double *val) {
    char buf[256];
    unsigned char len;

    if (fread(&len,1, 1, rdb) == 0) return -1;
    switch(len) {
    case 255: *val = -1.0/0.0; return 0;
    case 254: *val = 1.0/0.0; return 0;
    case 253: *val = 0.0/0.0; return 0;
    default:
        if (fread(buf,len, 1, rdb) == 0) return -1;
        buf[len] = '\0';
        sscanf(buf, "%lg", val);
        return 0;
    }
}

/* Use rdbLoadType() to load a TYPE in RDB format, but returns -1 if the
 * type is not specifically a valid Object Type. */
int rdbLoadObjectType(FILE *rdb) {
    int type;
    if ((type = rdbLoadType(rdb)) == -1) return -1;
    if (!rdbIsObjectType(type)) return -1;
    return type;
}

uint64_t nextPower(uint64_t x) {
    uint64_t power = 1;
    while (power <= x) {
        power = power << 1;
    }
    return power;
}

int zsetRandomLevel() {
    int level = 1;
    int rint = rand();
    while (rint < ZSKIPLIST_P * RAND_MAX) {
        level += 1;
        rint = rand();
    }
    if (level < ZSKIPLIST_MAXLEVEL) {
        return level;
    }
    else {
        return ZSKIPLIST_MAXLEVEL;
    }
}

/*
    Loads string metadata from the FILE rdb, 
    and moves the file pointer to the end of the string.
    
    - len will contain the length of the string
    - memory will contain the memory this string would consume if loaded in memory
    - savingsIfCompressed will contain the savings 
        if this string were compressed on client side
        before being saved in redis
    - header - a 10 byte header, loaded as 5 uint16_t 
*/
int rdbLoadStringMetadata(FILE *rdb, uint64_t *outLength, 
                    uint64_t *outMemory, uint64_t *outSavingsIfCompressed, 
                    uint16_t *outHeader) {

    int isencoded;
    uint64_t memory, len, clen = 0;
    unsigned char buf[11];

    len = rdbLoadLen(rdb,&isencoded);
    if (isencoded) {
        if (len == RDB_ENC_INT8) {
            rdbSkip(rdb, 1);
            len = 0;
            memory = 0;
        }
        else if (len == RDB_ENC_INT16) {
            rdbSkip(rdb, 2);
            len = 0;
            memory = 8;
        }
        else if (len == RDB_ENC_INT32) {
            rdbSkip(rdb, 4);
            len = 0;
            memory = 8;
        }
        else if (len == RDB_ENC_LZF) {
            if ((clen = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
            if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
            memory = len + 1 + 16 + 1;

            if (outHeader) {
                fread(buf, 11, 1, rdb);
                if (buf[0] < (1 << 5) && buf[0] > 10) {
                    memcpy(outHeader, buf+1, 10);
                    rdbSkip(rdb, clen - 11);
                }
                else {
                    /* 
                    Pay the cost of uncompressing the entire string 
                    We can optimize this branch later.
                    We have already read 11 bytes from rdb, so compensate accordingly
                    */
                    unsigned char *compressed = zmalloc(clen);
                    unsigned char *uncompressed = zmalloc(len);
                    for (int i=0; i<11; i++) {
                        compressed[i] = buf[i];
                    }
                    fread(compressed + 11, clen - 11, 1, rdb);
                    lzf_decompress(compressed,clen,uncompressed,len);
                    memcpy(outHeader, uncompressed, 10);
                    zfree(compressed);
                    zfree(uncompressed);
                }
            }
            else {
                rdbSkip(rdb, clen);
            }
        }
        else {
            rdbExitReportCorruptRDB("Unknown RDB string encoding type %d",len);
        }
    }
    else {
        if (outHeader) {
            fread(outHeader, 10, 1, rdb);
            rdbSkip(rdb, len - 10);
        }
        else {
            rdbSkip(rdb, len);
        }
        memory = len + 1 + 16 + 1;
    }

    *outLength = len;
    *outMemory = memory;
    if (clen > 0) {
        *outSavingsIfCompressed = len - clen;
    }
    else {
        *outSavingsIfCompressed = 0;
    }
    return 0;
}

uint64_t rdbMemoryForString(FILE *rdb) {
    int isencoded;
    uint64_t len, clen;

    len = rdbLoadLen(rdb,&isencoded);
    if (isencoded) {
        switch(len) {
        case RDB_ENC_INT8:
            rdbSkip(rdb, 1);
            return 0;
        case RDB_ENC_INT16:
            rdbSkip(rdb, 2);
            return 8;
        case RDB_ENC_INT32:
            rdbSkip(rdb, 4);
            return 8;
        case RDB_ENC_LZF:
            if ((clen = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
            if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
            rdbSkip(rdb, clen);
            break;
        default:
            rdbExitReportCorruptRDB("Unknown RDB string encoding type %d",len);
        }
    }
    else {
        rdbSkip(rdb, len);
    }
    /* 
    At this point, we have a string of length len 
    For now, we implement a simplistic heuristic for memory
    TODO: implement malloc overheads
    */
    return len + 1 + 16 + 1;
}

uint64_t topLevelObjectOverhead(uint64_t memoryForKey, int hasExpiry) {
    uint64_t memory = HASHTABLE_ENTRY_OVERHEAD + ROBJ_OVERHEAD;
    memory += memoryForKey;
    if (hasExpiry) {
        memory += KEY_EXPIRY_OVERHEAD;
    }
    return memory;
}

/* 
    Finds the memory used by a redis object.
    
    rdbtype is the type of object to load
    rdb is a reference to the RDB FILE

    len is the number of elements/key=value pairs in the data structure. 
        For strings, it is the length of the string.
    memory is the memory used by this obect in bytes
    savingsIfCompressed is potential memory saved 
        if this object was compressed before storing in redis
    maxLengthOfElement is the length of the largest element/field/value
         in this object. For string, it is length of string.
*/
int rdbMemoryForObject(int rdbtype, FILE *rdb, MemoryEntry *me) {

    me->bytes = me->lenLargestElement = me->savingsIfCompressed = me->length = 0;
    me->savingsIfQuicklistIsCompressed = 0;
    me->savingsIfZiplist = 0;
    me->savingsIfIntset = 0;
    me->savingsIfHashToList = 0;
    me->savingsIfHashHadSmallFieldNames = 0;

    /* 
    e stands for "element"
    These variables are similar to the ones above, 
    except they are for elements within this object
    */
    uint64_t eLen, eMemory, eSavingsIfCompressed;
    
    uint64_t numElements = 0;

    uint64_t sumLengthOfFields = 0;
    uint64_t sumLengthOfValues = 0;

    /*
        For ziplist, to find out the number of elements
        we load the first 10 bytes of the header
    */
    uint16_t zipListHeader[5];

    if (rdbtype == RDB_TYPE_STRING) {
        rdbLoadStringMetadata(rdb, &me->length, &me->bytes, &me->savingsIfCompressed, NULL);
    } else if (rdbtype == RDB_TYPE_LIST) {
        /* Read list value */
        if ((numElements = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;

        me->length = numElements;
        me->bytes += LINKEDLIST_OVERHEAD;
        me->bytes += LINKEDLIST_ITEM_OVERHEAD * numElements;

        /* skip every single element of the list */
        while(numElements--) {
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, NULL);
            sumLengthOfFields += eLen;
            me->bytes += eMemory;
            me->savingsIfCompressed += eSavingsIfCompressed;
            if (eLen > me->lenLargestElement) {
                me->lenLargestElement = eLen;
            }
        }

        me->savingsIfZiplist = me->bytes - sumLengthOfFields;

    } else if (rdbtype == RDB_TYPE_SET) {
        if ((numElements = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;

        me->length = numElements;
        me->bytes += HASHTABLE_OVERHEAD(numElements);
        me->bytes += HASHTABLE_ENTRY_OVERHEAD * numElements;
        
        /*
        
        TODO: decide if its int16, int32 or int64
        For not, assume it's it int32, a reasonable expectation

        TODO: add intset overheads
        */
        me->savingsIfIntset = me->bytes - numElements * 4;

        unsigned int i;
        /* Load every single element of the set */
        for (i = 0; i < numElements; i++) {
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, NULL);
            me->bytes += eMemory;
            me->savingsIfCompressed += eSavingsIfCompressed;
            if (eLen > me->lenLargestElement) {
                me->lenLargestElement = eLen;
            }
        }
    } else if (rdbtype == RDB_TYPE_ZSET_2 || rdbtype == RDB_TYPE_ZSET) {
        double score;
        if ((numElements = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
        me->length = numElements;

        me->bytes += SKIPLIST_OVERHEAD(numElements);
        if (rdbtype == RDB_TYPE_ZSET) {
            me->bytes += (SKIPLIST_ENTRY_OVERHEAD+4) * numElements;
        }
        else if (rdbtype == RDB_TYPE_ZSET_2) {
            me->bytes += (SKIPLIST_ENTRY_OVERHEAD+8) * numElements;
        }

        /* Load every single element of the sorted set. */
        while(numElements--) {
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, NULL);
            me->bytes += eMemory;
            me->savingsIfCompressed += eSavingsIfCompressed;
            sumLengthOfFields += eLen;
            if (eLen > me->lenLargestElement) {
                me->lenLargestElement = eLen;
            }

            if (rdbtype == RDB_TYPE_ZSET_2) {
                rdbSkip(rdb,sizeof(double));
                sumLengthOfValues += 8;
            } else {
                /*
                TODO: implement a skip function
                For now, we just read the double and ignore it
                */
                rdbLoadDoubleValue(rdb,&score);
                sumLengthOfValues += 4;
            }

            /*
            TODO: add ziplist overheads
            */
            me->savingsIfZiplist = me->bytes - (sumLengthOfValues + sumLengthOfFields);
        }
    } else if (rdbtype == RDB_TYPE_HASH) {
        if ((numElements = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
        me->bytes += HASHTABLE_OVERHEAD(numElements);
        me->bytes += HASHTABLE_ENTRY_OVERHEAD * numElements;
        me->length = numElements;

        while (numElements > 0) {
            numElements--;
            /* Read Field Name */
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, NULL);
            me->bytes += eMemory;
            me->savingsIfCompressed += eSavingsIfCompressed;
            me->length = eLen;
            sumLengthOfFields += eLen;
            if (eLen > me->lenLargestElement) {
                me->lenLargestElement = eLen;
            }
            
            /* Read Value */
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, NULL);
            me->bytes += eMemory;
            me->savingsIfCompressed += eSavingsIfCompressed;
            sumLengthOfValues += eLen;
            if (eLen > me->lenLargestElement) {
                me->lenLargestElement = eLen;
            }
            /*
            TODO: add ziplist overheads
            */
            me->savingsIfZiplist = me->bytes - (sumLengthOfValues + sumLengthOfFields);
            /*
            TODO: this assumes the new fields will have an average length of 5 bytes
            */
            me->savingsIfHashHadSmallFieldNames = sumLengthOfFields - me->length * 5;
        }
    } else if (rdbtype == RDB_TYPE_LIST_QUICKLIST) {
        if ((numElements = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
        me->bytes += QUICKLIST_OVERHEAD;
        me->bytes += QUICKLIST_ITEM_OVERHEAD * numElements;
        
        /* Don't compute maxLengthOfElement, use the default*/
        me->lenLargestElement = 512;

        unsigned int i = numElements;
        while (i--) {
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, zipListHeader);
            me->bytes += eMemory;
            
            /*
            If compression is enabled on a quicklist, the head and tail nodes
            will not be compressed. So we skip head and tail nodes.
            */
            if (i != numElements && i != 0) {
                me->savingsIfQuicklistIsCompressed += eSavingsIfCompressed;
            }

            /*
             ziplist header, if treated as uint16_t, 
                the 5th element represents the number of elements
                in the ziplist
            */
            me->length += zipListHeader[4];
        }
    } else if (rdbtype == RDB_TYPE_HASH_ZIPMAP  ||
               rdbtype == RDB_TYPE_LIST_ZIPLIST ||
               rdbtype == RDB_TYPE_SET_INTSET   ||
               rdbtype == RDB_TYPE_ZSET_ZIPLIST ||
               rdbtype == RDB_TYPE_HASH_ZIPLIST)
    {
        me->bytes = rdbMemoryForString(rdb);
    } else {
        rdbExitReportCorruptRDB("Unknown RDB encoding type %d",rdbtype);
    }
    return 0;
}

int getDataTypeAndEncoding(int type, const char **logicalType, const char **encoding) {
    *logicalType = DATATYPES[type];
    *encoding = ENCODINGS[type];
    return 0;
}

void initStats(Statistics *stats) {
    stats->totalMemory = stats->totalKeys = 0;
    for(int i=0; i<NUMBER_OF_ENCODINGS; i++) {
        stats->memoryByEncoding[i] = stats->countKeysByEncoding[i] = 0;
    }

    for(int i=0; i < NUMBER_OF_NATIVE_DATATYPE; i++){
		stats->dataTypeSummary[i].totalMemory = stats->dataTypeSummary[i].totalKeys = 0;
	}

    for(int i=0; i < TOP_KEYS_COUNT; i++){
		stats->topKeysByMemory[i].bytes = 0;
	}
}


int findPositionOfRecord(MemoryEntry meArr[], MemoryEntry *me, int low, int high) {
	if (meArr[high].bytes >= me->bytes)
		return -1;

	while (low <= high) {
		int mid = (low + high)/2;
		if (meArr[mid].bytes == me->bytes) {
			return mid;
		}

		if(meArr[mid].bytes == 0 ) {
			high=mid;
		}

		if (meArr[mid].bytes < me->bytes) {
			high = mid-1;
		} else {
			low = mid+1;
		}
	}
	return low;
}

void addTopKeysByMemory(MemoryEntry meArr[], MemoryEntry *me, int low, int high) {
	int index = findPositionOfRecord(meArr, me, low, high);
	if(index != -1) {
		memmove(&(meArr[index+1]), &(meArr[index]), (TOP_KEYS_COUNT-index-1)*sizeof(MemoryEntry));
		meArr[index] = *me;
	}
}

void updateStats(MemoryEntry *me, Statistics *stats) {
	int index = -1;
    stats->totalMemory += me->bytes;
    stats->totalKeys++;

    stats->memoryByEncoding[me->encdType] += me->bytes;
    stats->countKeysByEncoding[me->encdType]++;

    if (strncmp(me->dataType, NATIVEDATATYPES[0], strlen(NATIVEDATATYPES[0])) == 0) {
    	index = 0;
	} else if (strncmp(me->dataType, NATIVEDATATYPES[1], strlen(NATIVEDATATYPES[1])) == 0) {
		index = 1;
	} else if (strncmp(me->dataType, NATIVEDATATYPES[2], strlen(NATIVEDATATYPES[2])) == 0) {
		index = 2;
	} else if (strncmp(me->dataType, NATIVEDATATYPES[3], strlen(NATIVEDATATYPES[3])) == 0) {
		index = 3;
	} else if (strncmp(me->dataType, NATIVEDATATYPES[4], strlen(NATIVEDATATYPES[4])) == 0) {
		index = 4;
	}

	if(index != -1) {
		stats->dataTypeSummary[index].totalMemory += me->bytes;
		stats->dataTypeSummary[index].totalKeys += 1;
	}

    addTopKeysByMemory(stats->topKeysByMemory, me, 0, TOP_KEYS_COUNT-1);
}

void printStats(Statistics *stats, FILE *jsonOut) {
	fprintf (jsonOut, "{ \"summary\" : {");
	fprintf (jsonOut, " \"totalSizeInBytes\" : %llu,", stats->totalMemory);
	fprintf (jsonOut, " \"generatedTime\" : \"%s\",", "------");
	fprintf (jsonOut, " \"numKeys\" : %llu,", stats->totalKeys);
	fprintf (jsonOut, " \"dataTypeStats\" : {");

	for(int i=0; i< NUMBER_OF_NATIVE_DATATYPE; i++){
		fprintf (jsonOut, " \"%s\" : { \"count\": %llu, \"totalSizeInBytes\" : %llu }", NATIVEDATATYPES[i], stats->dataTypeSummary[i].totalKeys, stats->dataTypeSummary[i].totalMemory);
		if(i != NUMBER_OF_NATIVE_DATATYPE-1)
			fprintf (jsonOut, ",");
	}

	fprintf (jsonOut, " }}");
	fprintf (jsonOut, " }\n");

//    printf("Total Memory = %llu\n", stats->totalMemory);
//    printf("Total Keys = %llu\n", stats->totalKeys);

//    for(int i=0; i<NUMBER_OF_ENCODINGS; i++){
//        if (ENCODINGS[i] == NULL) continue;
//
//        printf("Memory for %s = %llu\n", ENCODINGS[i], stats->memoryByEncoding[i]);
//        printf("Keys for %s = %llu\n", ENCODINGS[i], stats->countKeysByEncoding[i]);
//    }
//
//    for(int i=0; i< TOP_KEYS_COUNT; i++){
//    	printf("Max Final memory %d==%llu\n", i, stats->topKeysByMemory[i].bytes);
//    }
//
//    for(int i=0; i< NUMBER_OF_NATIVE_DATATYPE; i++){
//		printf("Datatype Count Memory %s==%llu %llu\n", NATIVEDATATYPES[i], stats->dataTypeSummary[i].totalKeys, stats->dataTypeSummary[i].totalMemory);
//	}
}

int rdbMemoryAnalysisInternal(FILE *rdb, FILE *csv, FILE *jsonOut, uint64_t defaultSnapshotTime) {
    uint64_t dbid;
    int type, rdbver;
    char buf[1024];
    const char *dataType;
    const char *encoding;
    unsigned char header[11];
    int64_t expiretime = -1;
    MemoryEntry me;
    Statistics stats;
    initStats(&stats);

    /*
        This is the time this snapshot was created.
        We initialize this in this order:
        - If there is an aux field in the RDB, we use it
        - Otherwise, we use the provided defaultSnapshotTime
    */
    uint64_t snapshotTime = defaultSnapshotTime * 1000;
    uint64_t savingsIfCompressed = 0;
    uint64_t len = 0, maxLengthOfElement = -1;
    uint64_t keyMemory = 0, valueMemory = 0;
    
    if (fread(buf,9, 1, rdb) == 0) goto eoferr;
    buf[9] = '\0';
    rdbver = atoi(buf+5);

    /* Print CSV Header */
    fprintf(csv, "\"database\",\"type\",\"key\",\"size_in_bytes\",\"encoding\",\"num_elements\",\"len_largest_element\",\"expiry\",\"savings_if_compressed\",\"savings_if_quicklist_is_compressed\",\"savings_if_ziplist\",\"savings_if_intset\",\"savings_if_hash_to_list\",\"savings_if_hash_had_small_field_names\"\n");

    while(1) {
        expiretime = -1;

        /* Read type. */
        if ((type = rdbLoadType(rdb)) == -1) goto eoferr;

        /* Handle special types. */
        if (type == RDB_OPCODE_EXPIRETIME) {
            /* EXPIRETIME: load an expire associated with the next key
             * to load. Note that after loading an expire we need to
             * load the actual type, and continue. */
            if ((expiretime = rdbLoadTime(rdb)) == -1) goto eoferr;
            /* We read the time so we need to read the object type again. */
            if ((type = rdbLoadType(rdb)) == -1) goto eoferr;
            /* the EXPIRETIME opcode specifies time in seconds, so convert
             * into milliseconds. */
            expiretime *= 1000;
        } else if (type == RDB_OPCODE_EXPIRETIME_MS) {
            /* EXPIRETIME_MS: milliseconds precision expire times introduced
             * with RDB v3. Like EXPIRETIME but no with more precision. */
            if ((expiretime = rdbLoadMillisecondTime(rdb)) == -1) goto eoferr;
            /* We read the time so we need to read the object type again. */
            if ((type = rdbLoadType(rdb)) == -1) goto eoferr;
        } else if (type == RDB_OPCODE_EOF) {
            /* EOF: End of file, exit the main loop. */
            break;
        } else if (type == RDB_OPCODE_SELECTDB) {
            dbid = rdbLoadLen(rdb,NULL);
            continue;
        } else if (type == RDB_OPCODE_RESIZEDB) {
            rdbLoadLen(rdb,NULL);
            rdbLoadLen(rdb,NULL);
            continue; /* Read type again. */
        } else if (type == RDB_OPCODE_AUX) {
            char *key = rdbLoadPlainString(rdb);
            char *value = rdbLoadPlainString(rdb);
            if (!strcasecmp(key,"ctime")) {
                snapshotTime = (uint64_t)strtoll(value, NULL, 10);
                /*Convert to milliseconds, because expiry keys are converted to ms*/
                snapshotTime = snapshotTime * 1000;
            }
            continue; /* Read type again. */
        }

        /* We have the key and memory
        *  Need the following:
        *   expiry -> we have the absolute unix time. 
        *       We want "expires in 4 hours" instead of "expires at such and such time"
        *       To do so, we need to store the snapshot time ("ctime" aux field),
        *       and then subtract this from the absolute expiry time in rdb
        *        */
        /* Read key */
        sds key = rdbLoadString(rdb, &keyMemory, &savingsIfCompressed);

        /* TODO: sdscatrepr is a very slow function call. 
            Replace with a more optimal version
        */
        //key = sdscatrepr(sdsempty(), key, sdslen(key));
        rdbMemoryForObject(type, rdb, &me);
        getDataTypeAndEncoding(type, &dataType, &encoding);
        
        me.bytes = keyMemory + me.bytes;

        if (expiretime != -1) {
            expiretime = expiretime - snapshotTime;
        }
        me.encdType = type;
        me.dataType = dataType;
        me.key = key;
        updateStats(&me, &stats);
        
        fprintf(csv, "\"%llu\",\"%s\",%s,\"%llu\",\"%s\",\"%llu\",\"%llu\",\"%lld\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\"\n", 
            dbid, dataType, key, 
            me.bytes, encoding, me.length, me.lenLargestElement, expiretime, me.savingsIfCompressed,
            me.savingsIfQuicklistIsCompressed, me.savingsIfZiplist, me.savingsIfIntset,
            me.savingsIfHashToList, me.savingsIfHashHadSmallFieldNames
            );
        sdsfree(key);
    }
    
    printStats(&stats, jsonOut);
    return 0;

eoferr: /* unexpected end of file is handled here with a fatal exit */
    //serverLog(LL_WARNING,"Short read or OOM loading DB. Unrecoverable error, aborting now.");
    rdbExitReportCorruptRDB("Unexpected EOF reading RDB file");
    return -1; /* Just to avoid warning */
}

int rdbMemoryAnalysis(char *rdbFile, char *csvFile, char *jsonFile) {
    FILE *fp, *out, *jsonOut;
    int retval;
    uint64_t defaultSnapshotTime;
    struct stat rdbStat;

    if ((fp = fopen(rdbFile,"rb")) == NULL) return -1;
    if ((out = fopen(csvFile,"w")) == NULL) return -1;
    if ((jsonOut = fopen(jsonFile,"w")) == NULL) return -1;
    
    /*
        Read file last modified timestamp as a simple heuristic for 
        when the snapshot was created. 
        This is good and bad. 
        - If the file was copied to another location, this value is garbage
        - If the file was generated by redis, it's a good enough heuristic
    */
    fstat(fileno(fp), &rdbStat);
    defaultSnapshotTime = rdbStat.st_mtime;
    
    retval = rdbMemoryAnalysisInternal(fp, out, jsonOut, defaultSnapshotTime);
    fclose(fp);
    fclose(out);
    fclose(jsonOut);
    return retval;
}

int main(int argc, char **argv) {
	return rdbMemoryAnalysis(argv[1], argv[2], argv[3]);
}
