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
sds rdbLoadIntegerObject(FILE *rdb, int enctype, size_t *lenptr) {
    
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
    if (lenptr) *lenptr = len;
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
void *rdbLoadLzfStringObject(FILE *rdb, size_t *lenptr) {
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
    return val;

err:
    zfree(c);
    zfree(val);
    return NULL;
}

/* Load a SDS string from an RDB file according to flags:
 */
sds rdbLoadString(FILE *rdb, size_t *lenptr) {
    int isencoded;
    uint64_t len;

    len = rdbLoadLen(rdb,&isencoded);
    if (isencoded) {
        switch(len) {
        case RDB_ENC_INT8:
        case RDB_ENC_INT16:
        case RDB_ENC_INT32:
            return rdbLoadIntegerObject(rdb,len, lenptr);
        case RDB_ENC_LZF:
            return rdbLoadLzfStringObject(rdb,lenptr);
        default:
            rdbExitReportCorruptRDB("Unknown RDB string encoding type %d",len);
        }
    }

    void *buf = sdsnewlen(NULL,len);
    if (lenptr) *lenptr = len;
    if (len && fread(buf,len, 1, rdb) == 0) {
        sdsfree(buf);
        return NULL;
    }
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
    uint64_t len;
    unsigned int i;
    uint64_t memory = 0;
    double score;

    if (rdbtype == RDB_TYPE_STRING) {
        memory = rdbMemoryForString(rdb);
    } else if (rdbtype == RDB_TYPE_LIST) {
        /* Read list value */
        if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;

        memory += LINKEDLIST_OVERHEAD;
        memory += LINKEDLIST_ITEM_OVERHEAD * len;

        /* skip every single element of the list */
        while(len--) {
            memory += rdbMemoryForString(rdb);
        }

    } else if (rdbtype == RDB_TYPE_SET) {
        /* Read Set value */
        if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;

        memory += HASHTABLE_OVERHEAD(len);
        memory += HASHTABLE_ENTRY_OVERHEAD * len;

        /* Load every single element of the set */
        for (i = 0; i < len; i++) {
            memory += rdbMemoryForString(rdb);
        }
    } else if (rdbtype == RDB_TYPE_ZSET_2 || rdbtype == RDB_TYPE_ZSET) {
        /* Read list/set value. */
        uint64_t zsetlen;
        
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
            memory += rdbMemoryForString(rdb);

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
            memory += rdbMemoryForString(rdb);
            memory += rdbMemoryForString(rdb);
        }
    } else if (rdbtype == RDB_TYPE_LIST_QUICKLIST) {
        if ((len = rdbLoadLen(rdb,NULL)) == RDB_LENERR) return -1;
        memory += QUICKLIST_OVERHEAD;
        memory += QUICKLIST_ITEM_OVERHEAD * len;

        while (len--) {
            memory += rdbMemoryForString(rdb);
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

/* Load an RDB file 'rdb'. On success C_OK is returned,
 * otherwise C_ERR is returned and 'errno' is set accordingly. */
int rdbLoadFromFile(FILE *rdb) {
    uint64_t dbid;
    int type, rdbver;
    char buf[1024];
    long long expiretime;
    uint64_t memory;

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
            rdbLoadLen(rdb,NULL);
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
        sds key = rdbLoadString(rdb, NULL);
        printf("%s,", key);
        sdsfree(key);
        memory = rdbMemoryForObject(type,rdb);
        printf("%" PRIu64 "\n", memory);
    }

    return 0;

eoferr: /* unexpected end of file is handled here with a fatal exit */
    //serverLog(LL_WARNING,"Short read or OOM loading DB. Unrecoverable error, aborting now.");
    rdbExitReportCorruptRDB("Unexpected EOF reading RDB file");
    return -1; /* Just to avoid warning */
}

/* Like rdbLoadFromFile() but takes a filename instead of a FILE pointer. 
 */
int rdbLoad(char *filename) {
    FILE *fp;
    int retval;

    if ((fp = fopen(filename,"r")) == NULL) return -1;
    retval = rdbLoadFromFile(fp);
    fclose(fp);
    return retval;
}

int main(int argc, char **argv) {
    rdbLoad("askubuntu.rdb");
}