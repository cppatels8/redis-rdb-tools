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
#include <sys/param.h>
#include <stdarg.h> /* for va_list */
#include <stdio.h>
#include <stdlib.h>

#define rdbExitReportCorruptRDB(...) rdbCheckThenExit(__LINE__,__VA_ARGS__)

extern int rdbCheckMode;

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

long long rdbLoadMillisecondTime(FILE *rdb) {
    int64_t t64;
    if (fread(&t64, 8, 1, rdb) == 0) return -1;
    return (long long)t64;
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
sds rdbLoadString(FILE *rdb, uint64_t *memory, uint64_t *savingsIfCompressed) {
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

    void *buf = sdsnewlen(NULL,len);
    
    if (len && fread(buf,len, 1, rdb) == 0) {
        sdsfree(buf);
        return NULL;
    }
    /*
    TODO: refine this metric
    */
    *memory = len + 1 + 16 + 1;
    return buf;
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

            if (clen < 11) {
                printf("ERROR\n");
                printf("ERROR\n");
                printf("Did not expect clen to be less that 11\n");
                printf("ERROR\n");

            }
            if (outHeader) {
                fread(buf, 11, 1, rdb);
                if (buf[0] < (1 << 5) && buf[0] > 10) {
                    printf("LZF, literal copy\n");
                    for (int i=0; i<10; i++) {
                        outHeader[i] = buf[i+1];
                    }
                    rdbSkip(rdb, clen - 11);
                }
                else {
                    printf("LZF, full decompress\n");
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
                    printf("Uncompressed successfully");
                    for (int i=0; i<10; i++) {
                        outHeader[i] = uncompressed[i];
                    }
                    zfree(compressed);
                    zfree(uncompressed);
                    printf("Finished freeing compressed and uncompressed");
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
            printf("uncompressed string, simple fread\n");
            fread(outHeader, 10, 1, rdb);
            rdbSkip(rdb, len - 10);
        }
        else {
            rdbSkip(rdb, len);
        }
        memory = len + 1 + 16 + 1;
    }

    printf("Trying to write out parameters\n");
    *outLength = len;
    *outMemory = memory;
    if (clen > 0) {
        *outSavingsIfCompressed = len - clen;
    }
    else {
        *outSavingsIfCompressed = 0;
    }
    if (outHeader) {
        printf("outHeader = %d", outHeader[4]);
    }
    printf("Done writing out parameters\n");

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

/* Load a Redis object of the specified type from the specified file.
 * On success a newly allocated object is returned, otherwise NULL. */
uint64_t rdbMemoryForObject(int rdbtype, FILE *rdb) {
    
    /*
        len is the number of elements/key=value pairs in the data structure. 
            For strings, it is the length of the string.
        memory is the memory used by this obect in bytes
        savingsIfCompressed is potential memory saved 
            if this object was compressed before storing in redis
        maxLengthOfElement is the length of the largest element/field/value
             in this object. For string, it is length of string.

    */    
    uint64_t len = 0, memory = 0, savingsIfCompressed = 0;
    uint64_t maxLengthOfElement = -1;

    /* 
        e stands for "element"
        These variables are similar to the ones above, 
        except they are for elements within this object
    */
    uint64_t eLen, eMemory, eSavingsIfCompressed;
    
    /*
        For ziplist, to find out the number of elements
        we load the first 10 bytes of the header
    */
    uint16_t zipListHeader[5];

    printf("%d", rdbtype);

    if (rdbtype == RDB_TYPE_STRING) {
        rdbLoadStringMetadata(rdb, &len, &memory, &savingsIfCompressed, NULL);
    } else if (rdbtype == RDB_TYPE_LIST) {
        /* Read list value */
        if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;

        memory += LINKEDLIST_OVERHEAD;
        memory += LINKEDLIST_ITEM_OVERHEAD * len;

        /* skip every single element of the list */
        while(len--) {
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, NULL);
            memory += eMemory;
            savingsIfCompressed += eSavingsIfCompressed;
            if (eLen > maxLengthOfElement) {
                maxLengthOfElement = eLen;
            }
        }

    } else if (rdbtype == RDB_TYPE_SET) {
        if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;

        memory += HASHTABLE_OVERHEAD(len);
        memory += HASHTABLE_ENTRY_OVERHEAD * len;

        unsigned int i;
        /* Load every single element of the set */
        for (i = 0; i < len; i++) {
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, NULL);
            memory += eMemory;
            savingsIfCompressed += eSavingsIfCompressed;
            if (eLen > maxLengthOfElement) {
                maxLengthOfElement = eLen;
            }
        }
    } else if (rdbtype == RDB_TYPE_ZSET_2 || rdbtype == RDB_TYPE_ZSET) {
        uint64_t zsetlen;
        double score;

        if ((zsetlen = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
        
        memory += SKIPLIST_OVERHEAD(zsetlen);
        if (rdbtype == RDB_TYPE_ZSET) {
            memory += (SKIPLIST_ENTRY_OVERHEAD+4) * zsetlen;
        }
        else if (rdbtype == RDB_TYPE_ZSET_2) {
            memory += (SKIPLIST_ENTRY_OVERHEAD+8) * zsetlen;
        }

        /* Load every single element of the sorted set. */
        while(zsetlen--) {
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, NULL);
            memory += eMemory;
            savingsIfCompressed += eSavingsIfCompressed;
            if (eLen > maxLengthOfElement) {
                maxLengthOfElement = eLen;
            }

            if (rdbtype == RDB_TYPE_ZSET_2) {
                rdbSkip(rdb,sizeof(double));
            } else {
                /*
                TODO: implement a skip function
                For now, we just read the double and ignore it
                */
                rdbLoadDoubleValue(rdb,&score);
            }
        }
    } else if (rdbtype == RDB_TYPE_HASH) {
        uint64_t len;
        
        if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
        memory += HASHTABLE_OVERHEAD(len);
        memory += HASHTABLE_ENTRY_OVERHEAD * len;
        
        while (len > 0) {
            len--;
            /* Read Field Name */
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, NULL);
            memory += eMemory;
            savingsIfCompressed += eSavingsIfCompressed;
            if (eLen > maxLengthOfElement) {
                maxLengthOfElement = eLen;
            }
            
            /* Read Value */
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, NULL);
            memory += eMemory;
            savingsIfCompressed += eSavingsIfCompressed;
            if (eLen > maxLengthOfElement) {
                maxLengthOfElement = eLen;
            }
        }
    } else if (rdbtype == RDB_TYPE_LIST_QUICKLIST) {
        uint64_t numOfZiplists = 0;
        if ((numOfZiplists = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
        printf("numOfZiplists = %llu\n", numOfZiplists);
        memory += QUICKLIST_OVERHEAD;
        memory += QUICKLIST_ITEM_OVERHEAD * numOfZiplists;
        
        /* Don't compute maxLengthOfElement, use the default*/
        maxLengthOfElement = 512;

        while (numOfZiplists--) {
            rdbLoadStringMetadata(rdb, &eLen, &eMemory, &eSavingsIfCompressed, zipListHeader);
            printf("rdbLoadStringMetadata completed successfully");
            memory += eMemory;
            savingsIfCompressed += eSavingsIfCompressed;

            /*
             ziplist header, if treated as uint16_t, 
                the 5th element represents the number of elements
                in the ziplist
            */
            printf("Tring to read length of zipListHeader");
            len += zipListHeader[4];
            printf("Completed reading length of zipListHeader");
        }
    } else if (rdbtype == RDB_TYPE_HASH_ZIPMAP  ||
               rdbtype == RDB_TYPE_LIST_ZIPLIST ||
               rdbtype == RDB_TYPE_SET_INTSET   ||
               rdbtype == RDB_TYPE_ZSET_ZIPLIST ||
               rdbtype == RDB_TYPE_HASH_ZIPLIST)
    {
        memory = rdbMemoryForString(rdb);
    } else {
        rdbExitReportCorruptRDB("Unknown RDB encoding type %d",rdbtype);
    }
    return memory;
}

int getDataTypeAndEncoding(int type, char **logicalType, char **encoding) {
    if (type == RDB_TYPE_STRING) {
        *logicalType = "string";
        *encoding = "string";
    }
    else if (type == RDB_TYPE_LIST) {
        *logicalType = "list";
        *encoding = "linkedlist";
    } 
    else if (type == RDB_TYPE_LIST_ZIPLIST) {
        *logicalType = "list";
        *encoding = "ziplist";
    }
    else if (type == RDB_TYPE_LIST_QUICKLIST) {
        *logicalType = "list";
        *encoding = "quicklist";
    }
    else if (type == RDB_TYPE_SET) {
        *logicalType = "set";
        *encoding = "hashtable";
    }
    else if (type == RDB_TYPE_SET_INTSET) {
        *logicalType = "set";
        *encoding = "intset";
    }
    else if (type == RDB_TYPE_ZSET_2) {
        *logicalType = "zset";
        *encoding = "skiplist";
    }
    else if (type == RDB_TYPE_ZSET) {
        *logicalType = "zset";
        *encoding = "skiplist";
    }
    else if (type == RDB_TYPE_ZSET_ZIPLIST) {
        *logicalType = "zset";
        *encoding = "ziplist";
    }
    else if (type == RDB_TYPE_HASH) {
        *logicalType = "hash";
        *encoding = "hashtable";
    }
    else if (type == RDB_TYPE_HASH_ZIPLIST) {
        *logicalType = "hash";
        *encoding = "ziplist";
    }
    else if (type == RDB_TYPE_HASH_ZIPMAP) {
        *logicalType = "hash";
        *encoding = "zipmap";
    }
    else {
        return -1;
    }

    return 0;
}
/* Load an RDB file 'rdb'. On success C_OK is returned,
 * otherwise C_ERR is returned and 'errno' is set accordingly. */
int rdbMemoryAnalysisInternal(FILE *rdb, FILE *csv) {
    uint64_t dbid;
    int type, rdbver;
    char buf[1024];
    char *dataType;
    char *encoding;
    unsigned char header[11];
    long long expiretime;
    uint64_t memory, savingsIfCompressed;

    if (fread(buf,9, 1, rdb) == 0) goto eoferr;
    buf[9] = '\0';
    rdbver = atoi(buf+5);

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
            rdbSkipStringObject(rdb);
            rdbSkipStringObject(rdb);
            continue; /* Read type again. */
        }

        /* We have the key and memory
        *  Need the following:
        *   expiry -> we have the absolute unix time. 
        *       We want "expires in 4 hours" instead of "expires at such and such time"
        *       To do so, we need to store the snapshot time ("ctime" aux field),
        *       and then subtract this from the absolute expiry time in rdb
        *
        *   database number => trivial
        *   data type => trivial
        *   encoding => trivial
        *   savingsIfCompressed => if compressed (length - compressed length) else 0
        *   length => simple for objects, more complex for embedded objects
        *   length_of_largest_element => very involved for embedded objects...
        *       ... but it is useless for embedded objects anyways, so we can skip.
        *   
        */
        /* Read key */
        sds key = rdbLoadString(rdb, &memory, &savingsIfCompressed);
        memory = rdbMemoryForObject(type,rdb);
        getDataTypeAndEncoding(type, &dataType, &encoding);
        fprintf(csv, "%llu,%s,%s,%llu,%s\n", dbid, dataType, key, memory, encoding);
        sdsfree(key);
    }
    
    return 0;

eoferr: /* unexpected end of file is handled here with a fatal exit */
    //serverLog(LL_WARNING,"Short read or OOM loading DB. Unrecoverable error, aborting now.");
    rdbExitReportCorruptRDB("Unexpected EOF reading RDB file");
    return -1; /* Just to avoid warning */
}

int rdbMemoryAnalysis(char *rdbFile, char *csvFile) {
    FILE *fp, *out;
    int retval;

    if ((fp = fopen(rdbFile,"rb")) == NULL) return -1;
    if ((out = fopen(csvFile,"w")) == NULL) return -1;
    retval = rdbMemoryAnalysisInternal(fp, out);
    fclose(fp);
    fclose(out);
    return retval;
}

int main(int argc, char **argv) {
    return rdbMemoryAnalysis("askubuntu.rdb", "askubuntu_memory.csv");
}