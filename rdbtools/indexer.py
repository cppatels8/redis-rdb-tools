from struct import pack, unpack
import io
import datetime
import re
import os
import random
import bisect
from collections import namedtuple
from iowrapper import IOWrapper
from distutils.version import StrictVersion

try:
    try:
        from cStringIO import StringIO as BytesIO
    except ImportError:
        from StringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO

try:
    import lzf
    HAS_PYTHON_LZF = True
except ImportError:
    HAS_PYTHON_LZF = False
    
REDIS_RDB_6BITLEN = 0
REDIS_RDB_14BITLEN = 1
REDIS_RDB_32BITLEN = 0x80
REDIS_RDB_64BITLEN = 0x81
REDIS_RDB_ENCVAL = 3

REDIS_RDB_OPCODE_AUX = 250
REDIS_RDB_OPCODE_RESIZEDB = 251
REDIS_RDB_OPCODE_EXPIRETIME_MS = 252
REDIS_RDB_OPCODE_EXPIRETIME = 253
REDIS_RDB_OPCODE_SELECTDB = 254
REDIS_RDB_OPCODE_EOF = 255

REDIS_RDB_TYPE_STRING = 0
REDIS_RDB_TYPE_LIST = 1
REDIS_RDB_TYPE_SET = 2
REDIS_RDB_TYPE_ZSET = 3
REDIS_RDB_TYPE_HASH = 4
REDIS_RDB_TYPE_ZSET_2 = 5  # ZSET version 2 with doubles stored in binary.
REDIS_RDB_TYPE_MODULE = 6
REDIS_RDB_TYPE_MODULE_2 = 7
REDIS_RDB_TYPE_HASH_ZIPMAP = 9
REDIS_RDB_TYPE_LIST_ZIPLIST = 10
REDIS_RDB_TYPE_SET_INTSET = 11
REDIS_RDB_TYPE_ZSET_ZIPLIST = 12
REDIS_RDB_TYPE_HASH_ZIPLIST = 13
REDIS_RDB_TYPE_LIST_QUICKLIST = 14

REDIS_RDB_ENC_INT8 = 0
REDIS_RDB_ENC_INT16 = 1
REDIS_RDB_ENC_INT32 = 2
REDIS_RDB_ENC_LZF = 3

REDIS_RDB_MODULE_OPCODE_EOF = 0   # End of module value.
REDIS_RDB_MODULE_OPCODE_SINT = 1
REDIS_RDB_MODULE_OPCODE_UINT = 2
REDIS_RDB_MODULE_OPCODE_FLOAT = 3
REDIS_RDB_MODULE_OPCODE_DOUBLE = 4
REDIS_RDB_MODULE_OPCODE_STRING = 5

DATA_TYPE_MAPPING = {
    0 : "string", 1 : "list", 2 : "set", 3 : "sortedset", 4 : "hash", 5 : "sortedset", 6 : "module", 7: "module",
    9 : "hash", 10 : "list", 11 : "set", 12 : "sortedset", 13 : "hash", 14 : "list"}

MemoryRecord = namedtuple('MemoryRecord', ['database', 'type', 'key', 'bytes', 'encoding','size', 'len_largest_element', 'expiry', 'is_compressed', 'compressed_length'])


ZSKIPLIST_MAXLEVEL=32
ZSKIPLIST_P=0.25
REDIS_SHARED_INTEGERS = 10000

class RedisMemoryAnalyzer(object):
    """
    Provides a detailed breakup of memory used by a redis instance 
    
    """
    def __init__(self, architecture=64, redis_version="3.2") :
        self.current_db = 0
        self.current_key = None
        self.expiry = None
        self.rdb_version = 0

        self._db_expires = 0
        self._redis_version = StrictVersion(redis_version)
        self._redis_version_gte_32 = (self._redis_version >= StrictVersion('3.2'))
        self._redis_version_lt_32 = (self._redis_version < StrictVersion('3.2'))
        self._redis_version_lt_4 =  (self._redis_version < StrictVersion('4.0'))
        self._total_internal_frag = 0
        if architecture == 64 or architecture == '64':
            self._pointer_size = 8
            self._long_size = 8
            self._architecture = 64
        elif architecture == 32 or architecture == '32':
            self._pointer_size = 4
            self._long_size = 4
            self._architecture = 32

    def analyze_redis_instance(self, host, port, password):
        pass

    def analyze_rdb(self, filename):
        """
        Parse a redis rdb dump file, and call methods in the 
        callback object during the parsing operation.
        """
        return self.get_memory_records(open(filename, "rb"))

    def get_memory_records(self, fd):
        with fd as f:
            verify_magic_string(f.read(5))
            self.rdb_version = get_rdb_version(f.read(4))
            
            while True:
                self.expiry = None
                data_type = read_unsigned_char(f)

                if data_type == REDIS_RDB_OPCODE_EXPIRETIME_MS:
                    self.expiry = to_datetime(read_unsigned_long(f) * 1000)
                    data_type = read_unsigned_char(f)
                elif data_type == REDIS_RDB_OPCODE_EXPIRETIME:
                    self.expiry = to_datetime(read_unsigned_int(f) * 1000000)
                    data_type = read_unsigned_char(f)

                if data_type == REDIS_RDB_OPCODE_SELECTDB:
                    self.current_db = read_length(f)
                    continue

                if data_type == REDIS_RDB_OPCODE_AUX:
                    for _ in range(2):
                        skip_string(f)
                    continue

                if data_type == REDIS_RDB_OPCODE_RESIZEDB:
                    for _ in range(2):
                        skip_length_field(f)
                    continue

                if data_type == REDIS_RDB_OPCODE_EOF:
                    if self.rdb_version >= 5:
                        skip_checksum(f)
                    break

                self.current_key = read_string(f)
                yield self.get_memory_for_obj(f, data_type)


    # Read an object for the stream
    # f is the redis file 
    # enc_type is the type of object
    def get_memory_for_obj(self, f, enc_type) :
        if enc_type == REDIS_RDB_TYPE_STRING:
            return self.memory_for_string(f)
        elif enc_type == REDIS_RDB_TYPE_LIST:
            return self.memory_for_list_linkedlist(f)
        elif enc_type == REDIS_RDB_TYPE_LIST_ZIPLIST:
            return self.memory_for_list_ziplist(f)
        elif enc_type == REDIS_RDB_TYPE_LIST_QUICKLIST:
            self.memory_for_list_quicklist(f)
        elif enc_type == REDIS_RDB_TYPE_SET:
            # A redis list is just a sequence of strings
            # We successively read strings from the stream and create a set from it
            # Note that the order of strings is non-deterministic
            length = read_length(f)
            # self._callback.start_set(self._key, length, self._expiry, info={'encoding':'hashtable'})
            for count in range(0, length):
                val = read_string(f)
                # self._callback.sadd(self._key, val)
            # self._callback.end_set(self._key)
        elif enc_type == REDIS_RDB_TYPE_SET_INTSET:
            self.memory_for_set_intset(f)
        elif enc_type == REDIS_RDB_TYPE_ZSET or enc_type == REDIS_RDB_TYPE_ZSET_2 :
            length = read_length(f)
            # self._callback.start_sorted_set(self._key, length, self._expiry, info={'encoding':'skiplist'})
            for count in range(0, length):
                val = read_string(f)
                score = read_double(f) if enc_type == REDIS_RDB_TYPE_ZSET_2 else read_float(f)
                # self._callback.zadd(self._key, score, val)
            # self._callback.end_sorted_set(self._key)
        elif enc_type == REDIS_RDB_TYPE_ZSET_ZIPLIST:
            return self.memory_for_zset_ziplist(f)
        elif enc_type == REDIS_RDB_TYPE_HASH:
            return self.memory_for_hash_hashtable(f)
        elif enc_type == REDIS_RDB_TYPE_HASH_ZIPMAP:
            self.read_zipmap(f)
        elif enc_type == REDIS_RDB_TYPE_HASH_ZIPLIST:
            return self.memory_for_hash_ziplist(f)
        elif enc_type == REDIS_RDB_TYPE_MODULE:
            raise Exception('read_object', 'Unable to read Redis Modules RDB objects (key %s)' % self._key)
        elif enc_type == REDIS_RDB_TYPE_MODULE_2:
            self.read_module(f)
        else:
            raise Exception('read_object', 'Invalid object type %d for key %s' % (enc_type, self.current_key))

    def memory_for_string(self, f):
        metadata = read_string_metadata(f)
        size = self.top_level_object_overhead(self.current_key, self.expiry)
        size += self.sizeof_string(metadata.length, metadata.is_number, metadata.is_shared_number)
        
        return MemoryRecord(
                self.current_db, "string", self.current_key, size,
                "string", metadata.length, metadata.length, self.expiry, 
                metadata.is_compressed, metadata.compressed_length
            )

    def memory_for_list_linkedlist(self, f):
        # A redis list is just a sequence of strings
        # We successively read strings from the stream and create a list from it
        # The lists are in order i.e. the first string is the head, 
        # and the last string is the tail of the list
        size = self.top_level_object_overhead(self.current_key, self.expiry)
        compressed_size = 0
        any_element_compressed = False
        length = read_length(f)
        for count in range(0, length):
            metadata = read_string_metadata(f)
            if metadata.is_compressed:
                any_element_compressed = True
                compressed_size = metadata.compressed_length
            size += self.sizeof_string(metadata.length, metadata.is_number, metadata.is_shared_number)
        
        size+= self.linkedlist_entry_overhead() * length
        size+= self.linkedlist_overhead()
        if self._redis_version_lt_4:
            size += self.robj_overhead() * length

        return MemoryRecord(
                self.current_db, "list", self.current_key, size,
                "linkedlist", length, metadata.length, self.expiry, 
                any_element_compressed, compressed_size
            )

    def memory_for_list_ziplist(self, f):
        raw_string = read_string(f)
        buff = BytesIO(raw_string)
        zlbytes = read_unsigned_int(buff)
        tail_offset = read_unsigned_int(buff)
        num_entries = read_unsigned_short(buff)
        
        size = self.top_level_object_overhead(self.current_key, self.expiry)
        size += len(raw_string)

        max_value_size = -1

        for x in range(0, num_entries):
            value_length = self.read_ziplist_entry_length(buff)
            if value_length > max_value_size:
                max_value_size = value_length

        zlist_end = read_unsigned_char(buff)
        if zlist_end != 255 : 
            raise Exception('read_ziplist', "Invalid zip list end - %d for key %s" % (zlist_end, self._key))

        return MemoryRecord(
                self.current_db, "list", self.current_key, size,
                "ziplist", num_entries, max_value_size, 
                self.expiry, 
                False, -1
            )        

    # TODO: Implement this
    def memory_for_list_quicklist(self, f):
        count = read_length(f)
        total_size = 0
        for i in range(0, count):
            raw_string = read_string(f)
            total_size += len(raw_string)
            buff = BytesIO(raw_string)
            zlbytes = read_unsigned_int(buff)
            tail_offset = read_unsigned_int(buff)
            num_entries = read_unsigned_short(buff)
            for x in range(0, num_entries):
                self.read_ziplist_entry(buff)
                # self._callback.rpush(self._key, self.read_ziplist_entry(buff))
            zlist_end = read_unsigned_char(buff)
            if zlist_end != 255:
                raise Exception('read_quicklist', "Invalid zip list end - %d for key %s" % (zlist_end, self.current_key))
        # self._callback.end_list(self._key, info={'encoding': 'quicklist', 'zips': count, 'sizeof_value': total_size})

    def memory_for_set_intset(self, f) :
        raw_string = read_string(f)
        buff = BytesIO(raw_string)
        encoding = read_unsigned_int(buff)
        num_entries = read_unsigned_int(buff)

        size = self.top_level_object_overhead(self.current_key, self.expiry)
        size += len(raw_string)

        # Since we have already loaded the string into memory
        # we don't have to skip any more bytes in the file stream
        # skip(f, num_entries * encoding)
        
        return MemoryRecord(
                self.current_db, "set", self.current_key, size,
                "intset%d" % encoding, num_entries, encoding, self.expiry, 
                False, -1
            )

    def memory_for_zset_ziplist(self, f) :
        raw_string = read_string(f)
        buff = BytesIO(raw_string)
        zlbytes = read_unsigned_int(buff)
        tail_offset = read_unsigned_int(buff)
        num_entries = read_unsigned_short(buff)
        if (num_entries % 2) :
            raise Exception('read_zset_from_ziplist', "Expected even number of elements, but found %d for key %s" % (num_entries, self._key))
        num_entries = num_entries // 2
        
        size = self.top_level_object_overhead(self.current_key, self.expiry)
        size += len(raw_string)

        max_key_size = -1

        for x in range(0, num_entries) :
            key_size = self.read_ziplist_entry_length(buff)
            _ = self.read_ziplist_entry_length(buff)
            if key_size > max_key_size:
                max_key_size = key_size
        
        zlist_end = read_unsigned_char(buff)
        if zlist_end != 255 : 
            raise Exception('read_zset_from_ziplist', "Invalid zip list end - %d for key %s" % (zlist_end, self._key))

        return MemoryRecord(
                self.current_db, "zset", self.current_key, size,
                "ziplist", num_entries, max_key_size, self.expiry, 
                False, -1
            )

    def memory_for_hash_hashtable(self, f):
        size = self.top_level_object_overhead(self.current_key, self.expiry)
        max_field_length = -1
        max_value_length = -1
        savings_if_compressed = 0

        length = read_length(f)
        for count in range(0, length):
            field = read_string_metadata(f)
            value = read_string_metadata(f)

            if field.length > max_field_length:
                max_field_length = field.length
            if value.length > max_value_length:
                max_value_length = value.length

            if value.is_compressed:
                savings_if_compressed += value.compressed_length

            field_size = self.sizeof_string(field.length, field.is_number, field.is_shared_number)
            value_size = self.sizeof_string(value.length, value.is_number, value.is_shared_number)
            size += field_size
            size += value_size
        
        size += self.hashtable_entry_overhead() * length
        if self._redis_version_lt_4:
            size += 2*self.robj_overhead() * length

        return MemoryRecord(
                self.current_db, "hash", self.current_key, size,
                "hashtable", size, max_value_length, self.expiry, 
                False, savings_if_compressed
            )

    def memory_for_hash_ziplist(self, f):
        raw_string = read_string(f)
        buff = BytesIO(raw_string)
        zlbytes = read_unsigned_int(buff)
        tail_offset = read_unsigned_int(buff)
        num_entries = read_unsigned_short(buff)
        if (num_entries % 2) :
            raise Exception('read_hash_from_ziplist', "Expected even number of elements, but found %d for key %s" % (num_entries, self._key))
        num_entries = num_entries // 2
        
        max_field_size = -1
        max_value_size = -1
        
        size = self.top_level_object_overhead(self.current_key, self.expiry)
        size += len(raw_string)

        # We now want to calculate the max field size and max value size
        # Note that we don't want the actual field or value, just their lengths
        for x in range(0, num_entries) :
            # self.read_ziplist_entry(buff)
            # self.read_ziplist_entry(buff)
            field_length = self.read_ziplist_entry_length(buff)
            value_length = self.read_ziplist_entry_length(buff)
            if field_length > max_field_size:
                max_field_size = field_length
            if value_length > max_value_size:
                max_value_size = value_length
            
        zlist_end = read_unsigned_char(buff)
        if zlist_end != 255 : 
            raise Exception('read_hash_from_ziplist', "Invalid zip list end - %d for key %s" % (zlist_end, self.current_key))
        
        return MemoryRecord(
                self.current_db, "hash", self.current_key, size,
                "ziplist", num_entries, max_value_size, 
                self.expiry, 
                False, -1
            )

    def read_ziplist_entry_length(self, f) :
        length = 0
        prev_length = read_unsigned_char(f)
        if prev_length == 254 :
            prev_length = read_unsigned_int(f)

        entry_header = read_unsigned_char(f)
        if (entry_header >> 6) == 0 :
            length = entry_header & 0x3F
            skip(f, length)
            return length
        elif (entry_header >> 6) == 1 :
            length = ((entry_header & 0x3F) << 8) | read_unsigned_char(f)
            skip(f, length)
            return length
        elif (entry_header >> 6) == 2 :
            length = read_unsigned_int_be(f)
            skip(f, length)
            return length
        elif (entry_header >> 4) == 12 :
            skip_signed_short(f)
            return self._long_size
        elif (entry_header >> 4) == 13 :
            skip_signed_int(f)
            return self._long_size
        elif (entry_header >> 4) == 14 :
            skip_signed_long(f)
            return self._long_size
        elif (entry_header == 240) :
            _ = read_24bit_signed_number(f)
            return self._long_size
        elif (entry_header == 254) :
            skip_signed_char(f)
            return self._long_size
        elif (entry_header >= 241 and entry_header <= 253) :
            return self._long_size
        else:
            raise Exception('read_ziplist_entry', 'Invalid entry_header %d for key %s' % (entry_header, self._key))

    def read_ziplist_entry(self, f) :
        length = 0
        value = None
        prev_length = read_unsigned_char(f)
        if prev_length == 254 :
            prev_length = read_unsigned_int(f)
        entry_header = read_unsigned_char(f)
        if (entry_header >> 6) == 0 :
            length = entry_header & 0x3F
            value = f.read(length)
        elif (entry_header >> 6) == 1 :
            length = ((entry_header & 0x3F) << 8) | read_unsigned_char(f)
            value = f.read(length)
        elif (entry_header >> 6) == 2 :
            length = read_unsigned_int_be(f)
            value = f.read(length)
        elif (entry_header >> 4) == 12 :
            value = read_signed_short(f)
        elif (entry_header >> 4) == 13 :
            value = read_signed_int(f)
        elif (entry_header >> 4) == 14 :
            value = read_signed_long(f)
        elif (entry_header == 240) :
            value = read_24bit_signed_number(f)
        elif (entry_header == 254) :
            value = read_signed_char(f)
        elif (entry_header >= 241 and entry_header <= 253) :
            value = entry_header - 241
        else :
            raise Exception('read_ziplist_entry', 'Invalid entry_header %d for key %s' % (entry_header, self._key))
        return value
        
    def read_zipmap(self, f) :
        raw_string = read_string(f)
        buff = io.BytesIO(bytearray(raw_string))
        num_entries = read_unsigned_char(buff)
        # self._callback.start_hash(self._key, num_entries, self._expiry, info={'encoding':'zipmap', 'sizeof_value':len(raw_string)})
        while True :
            next_length = self.read_zipmap_next_length(buff)
            if next_length is None :
                break
            key = buff.read(next_length)
            next_length = self.read_zipmap_next_length(buff)
            if next_length is None :
                raise Exception('read_zip_map', 'Unexepcted end of zip map for key %s' % self._key)        
            free = read_unsigned_char(buff)
            value = buff.read(next_length)
            try:
                value = int(value)
            except ValueError:
                pass
            
            skip(buff, free)
            # self._callback.hset(self._key, key, value)
        # self._callback.end_hash(self._key)

    def read_zipmap_next_length(self, f) :
        num = read_unsigned_char(f)
        if num < 254:
            return num
        elif num == 254:
            return read_unsigned_int(f)
        else:
            return None

    def read_module(self, f):
        # this method is based on the actual implementation in redis (src/rdb.c:rdbLoadObject)
        iowrapper = IOWrapper(f)
        iowrapper.start_recording_size()
        iowrapper.start_recording()
        length, encoding = read_length_with_encoding(iowrapper)
        # record_buffer = self._callback.start_module(self._key, _decode_module_id(length), self._expiry)
        record_buffer = False
        if not record_buffer:
            iowrapper.stop_recording()

        opcode = read_length(iowrapper)
        while opcode != REDIS_RDB_MODULE_OPCODE_EOF:
            if opcode == REDIS_RDB_MODULE_OPCODE_SINT or opcode == REDIS_RDB_MODULE_OPCODE_UINT:
                data = read_length(iowrapper)
            elif opcode == REDIS_RDB_MODULE_OPCODE_FLOAT:
                data = read_float(iowrapper)
            elif opcode == REDIS_RDB_MODULE_OPCODE_DOUBLE:
                data = read_double(iowrapper)
            elif opcode == REDIS_RDB_MODULE_OPCODE_STRING:
                data = read_string(iowrapper)
            else:
                raise Exception("Unknown module opcode %s" % opcode)
            # self._callback.handle_module_data(self._key, opcode, data)
            # read the next item in the module data type
            opcode = read_length(iowrapper)

        buffer = None
        if record_buffer:
            # prepand the buffer with REDIS_RDB_TYPE_MODULE_2 type
            buffer = pack('B', REDIS_RDB_TYPE_MODULE_2) + iowrapper.get_recorded_buffer()
            iowrapper.stop_recording()
        # self._callback.end_module(self._key, buffer_size=iowrapper.get_recorded_size(), buffer=buffer)

    ### Memory calculation functions
    def sizeof_real_string(self, str):
        try:
            val = int(str)
            return self.sizeof_string(-1, True, val < REDIS_SHARED_INTEGERS)
        except:
            return self.sizeof_string(len(str), False)

    def sizeof_string(self, len_of_str, is_number, is_shared_number=False):
        # https://github.com/antirez/redis/blob/unstable/src/sds.h
        if is_number: 
            if is_shared_number:
                return 0
            else:
                return 8

        if self._redis_version_lt_32:
            return self.malloc_overhead(len_of_str + 8 + 1)
        if len_of_str < 2**5:
            return self.malloc_overhead(len_of_str + 1 + 1)
        if len_of_str < 2**8:
            return self.malloc_overhead(len_of_str + 1 + 2 + 1)
        if len_of_str < 2**16:
            return self.malloc_overhead(len_of_str + 1 + 4 + 1)
        if len_of_str < 2**32:
            return self.malloc_overhead(len_of_str + 1 + 8 + 1)
        return self.malloc_overhead(len_of_str + 1 + 16 + 1)

    def top_level_object_overhead(self, key, expiry):
        # Each top level object is an entry in a dictionary, and so we have to include 
        # the overhead of a dictionary entry
        return self.hashtable_entry_overhead() + self.sizeof_real_string(key) +\
                     self.robj_overhead() + self.key_expiry_overhead(expiry)

    def key_expiry_overhead(self, expiry):
        # If there is no expiry, there isn't any overhead
        if not expiry:
            return 0
        self._db_expires += 1
        # Key expiry is stored in a hashtable, so we have to pay for the cost of a hashtable entry
        # The timestamp itself is stored as an int64, which is a 8 bytes
        return self.hashtable_entry_overhead() + 8
        
    def hashtable_overhead(self, size):
        # See  https://github.com/antirez/redis/blob/unstable/src/dict.h
        # See the structures dict and dictht
        # 2 * (3 unsigned longs + 1 pointer) + int + long + 2 pointers
        # 
        # Additionally, see **table in dictht
        # The length of the table is the next power of 2
        # When the hashtable is rehashing, another instance of **table is created
        # Due to the possibility of rehashing during loading, we calculate the worse 
        # case in which both tables are allocated, and so multiply
        # the size of **table by 1.5
        return 4 + 7*self.sizeof_long() + 4*self.sizeof_pointer() + self.next_power(size)*self.sizeof_pointer()*1.5
        
    def hashtable_entry_overhead(self):
        # See  https://github.com/antirez/redis/blob/unstable/src/dict.h
        # Each dictEntry has 2 pointers + int64
        return 2*self.sizeof_pointer() + 8
    
    def linkedlist_overhead(self):
        # See https://github.com/antirez/redis/blob/unstable/src/adlist.h
        # A list has 5 pointers + an unsigned long
        return self.sizeof_long() + 5*self.sizeof_pointer()

    def quicklist_overhead(self, zip_count):
        quicklist = 2*self.sizeof_pointer()+self.sizeof_long()+2*4
        quickitem = 4*self.sizeof_pointer()+self.sizeof_long()+2*4
        return quicklist + zip_count*quickitem

    def linkedlist_entry_overhead(self):
        # See https://github.com/antirez/redis/blob/unstable/src/adlist.h
        # A node has 3 pointers
        return 3*self.sizeof_pointer()

    def ziplist_header_overhead(self):
        # See https://github.com/antirez/redis/blob/unstable/src/ziplist.c
        # <zlbytes><zltail><zllen><entry><entry><zlend>
        return 4 + 4 + 2 + 1

    def ziplist_entry_overhead(self, value):
        # See https://github.com/antirez/redis/blob/unstable/src/ziplist.c
        if type(value) == int:
            header = 1
            if value < 12:
                size = 0
            elif value < 2**8:
                size = 1
            elif value < 2**16:
                size = 2
            elif value < 2**24:
                size = 3
            elif value < 2**32:
                size = 4
            else:
                size = 8
        else:
            size = len(value)
            if size <= 63:
                header = 1
            elif size <= 16383:
                header = 2
            else:
                header = 5
        # add len again for prev_len of the next record
        prev_len = 1 if size < 254 else 5
        return prev_len + header + size

    def skiplist_overhead(self, size):
        return 2*self.sizeof_pointer() + self.hashtable_overhead(size) + (2*self.sizeof_pointer() + 16)
    
    def skiplist_entry_overhead(self):
        return self.hashtable_entry_overhead() + 2*self.sizeof_pointer() + 8 + (self.sizeof_pointer() + 8) * self.zset_random_level()
    
    def robj_overhead(self):
        return self.sizeof_pointer() + 8
        
    def malloc_overhead(self, size):
        alloc = get_jemalloc_allocation(size)
        self._total_internal_frag += alloc - size
        return alloc

    def size_t(self):
        return self.sizeof_pointer()
        
    def sizeof_pointer(self):
        return self._pointer_size
        
    def sizeof_long(self):
        return self._long_size

    def next_power(self, size):
        power = 1
        while (power <= size) :
            power = power << 1
        return power
 
    def zset_random_level(self):
        level = 1
        rint = random.randint(0, 0xFFFF)
        while (rint < ZSKIPLIST_P * 0xFFFF):
            level += 1
            rint = random.randint(0, 0xFFFF)        
        if level < ZSKIPLIST_MAXLEVEL :
            return level
        else:
            return ZSKIPLIST_MAXLEVEL

    def element_length(self, element):
        if isinstance(element, int):
            return self._long_size
        if sys.version_info < (3,):
            if isinstance(element, long):
                return self._long_size
        return len(element)


### END OF RedisMemoryAnalyzer

def _decode_module_id(module_id):
    """
    decode module id to string
    based on @antirez moduleTypeNameByID function from redis/src/module.c
    :param module_id: 64bit integer
    :return: string
    """
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    name = [''] * 9
    module_id >>= 10
    for i in reversed(range(9)):
        name[i] = charset[module_id & 63]
        module_id >>= 6
    return ''.join(name)
        
def lzf_decompress(compressed, expected_length):
    if HAS_PYTHON_LZF:
        return lzf.decompress(compressed, expected_length)
    else:
        in_stream = bytearray(compressed)
        in_len = len(in_stream)
        in_index = 0
        out_stream = bytearray()
        out_index = 0

        while in_index < in_len :
            ctrl = in_stream[in_index]
            if not isinstance(ctrl, int) :
                raise Exception('lzf_decompress', 'ctrl should be a number %s' % str(ctrl))
            in_index = in_index + 1
            if ctrl < 32 :
                for x in range(0, ctrl + 1) :
                    out_stream.append(in_stream[in_index])
                    #sys.stdout.write(chr(in_stream[in_index]))
                    in_index = in_index + 1
                    out_index = out_index + 1
            else :
                length = ctrl >> 5
                if length == 7 :
                    length = length + in_stream[in_index]
                    in_index = in_index + 1

                ref = out_index - ((ctrl & 0x1f) << 8) - in_stream[in_index] - 1
                in_index = in_index + 1
                for x in range(0, length + 2) :
                    out_stream.append(out_stream[ref])
                    ref = ref + 1
                    out_index = out_index + 1
        if len(out_stream) != expected_length :
            raise Exception('lzf_decompress', 'Expected lengths do not match %d != %d' % (len(out_stream), expected_length))
        return bytes(out_stream)

# size classes from jemalloc 4.0.4 using LG_QUANTUM=3
jemalloc_size_classes = [
    8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
    1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192, 10240, 12288, 14336, 16384, 20480, 24576,
    28672, 32768, 40960, 49152, 57344, 65536, 81920, 98304, 114688,131072, 163840, 196608, 229376, 262144, 327680,
    393216, 458752, 524288, 655360, 786432, 917504, 1048576, 1310720, 1572864, 1835008, 2097152, 2621440, 3145728,
    3670016, 4194304, 5242880, 6291456, 7340032, 8388608, 10485760, 12582912, 14680064, 16777216, 20971520, 25165824,
    29360128, 33554432, 41943040, 50331648, 58720256, 67108864, 83886080, 100663296, 117440512, 134217728, 167772160,
    201326592, 234881024, 268435456, 335544320, 402653184, 469762048, 536870912, 671088640, 805306368, 939524096,
    1073741824, 1342177280, 1610612736, 1879048192, 2147483648, 2684354560, 3221225472, 3758096384, 4294967296,
    5368709120, 6442450944, 7516192768, 8589934592, 10737418240, 12884901888, 15032385536, 17179869184, 21474836480,
    25769803776, 30064771072, 34359738368, 42949672960, 51539607552, 60129542144, 68719476736, 85899345920,
    103079215104, 120259084288, 137438953472, 171798691840, 206158430208, 240518168576, 274877906944, 343597383680,
    412316860416, 481036337152, 549755813888, 687194767360, 824633720832, 962072674304, 1099511627776,1374389534720,
    1649267441664, 1924145348608, 2199023255552, 2748779069440, 3298534883328, 3848290697216, 4398046511104,
    5497558138880, 6597069766656, 7696581394432, 8796093022208, 10995116277760, 13194139533312, 15393162788864,
    17592186044416, 21990232555520, 26388279066624, 30786325577728, 35184372088832, 43980465111040, 52776558133248,
    61572651155456, 70368744177664, 87960930222080, 105553116266496, 123145302310912, 140737488355328, 175921860444160,
    211106232532992, 246290604621824, 281474976710656, 351843720888320, 422212465065984, 492581209243648,
    562949953421312, 703687441776640, 844424930131968, 985162418487296, 1125899906842624, 1407374883553280,
    1688849860263936, 1970324836974592, 2251799813685248, 2814749767106560, 3377699720527872, 3940649673949184,
    4503599627370496, 5629499534213120, 6755399441055744, 7881299347898368, 9007199254740992, 11258999068426240,
    13510798882111488, 15762598695796736, 18014398509481984, 22517998136852480, 27021597764222976,31525197391593472,
    36028797018963968, 45035996273704960, 54043195528445952, 63050394783186944, 72057594037927936, 90071992547409920,
    108086391056891904, 126100789566373888, 144115188075855872, 180143985094819840, 216172782113783808,
    252201579132747776, 288230376151711744, 360287970189639680, 432345564227567616, 504403158265495552,
    576460752303423488, 720575940379279360, 864691128455135232, 1008806316530991104, 1152921504606846976,
    1441151880758558720, 1729382256910270464, 2017612633061982208, 2305843009213693952, 2882303761517117440,
    3458764513820540928, 4035225266123964416, 4611686018427387904, 5764607523034234880, 6917529027641081856,
    8070450532247928832, 9223372036854775808, 11529215046068469760, 13835058055282163712, 16140901064495857664
]  # TODO: use different table depending oon the redis-version used

def get_jemalloc_allocation(size):
    idx = bisect.bisect_left(jemalloc_size_classes, size)
    alloc = jemalloc_size_classes[idx] if idx < len(jemalloc_size_classes) else size
    return alloc

def verify_magic_string(magic_string) :
    if magic_string != b'REDIS' :
        raise Exception('verify_magic_string', 'Invalid File Format')

def get_rdb_version(version_str) :
    version = int(version_str)
    if version < 1 or version > 8: 
        raise Exception('verify_version', 'Invalid RDB version number %d' % version)
    return version

def skip(f, free):
    if free :
        f.seek(free, os.SEEK_CUR)

def skip_key_and_object(f, data_type):
    skip_string(f)
    skip_object(f, data_type)

def skip_string(f):
    tup = read_length_with_encoding(f)
    length = tup[0]
    is_encoded = tup[1]
    bytes_to_skip = 0
    if is_encoded :
        if length == REDIS_RDB_ENC_INT8 :
            bytes_to_skip = 1
        elif length == REDIS_RDB_ENC_INT16 :
            bytes_to_skip = 2
        elif length == REDIS_RDB_ENC_INT32 :
            bytes_to_skip = 4
        elif length == REDIS_RDB_ENC_LZF :
            clen = read_length(f)
            l = read_length(f)
            bytes_to_skip = clen
    else :
        bytes_to_skip = length
    
    skip(f, bytes_to_skip)

def skip_float(f):
    dbl_length = read_unsigned_char(f)
    if dbl_length < 253:
        skip(f, dbl_length)
    
def skip_binary_double(f):
    skip(f, 8)

def skip_checksum(f):
    skip(f, 8)

def skip_signed_char(f):
    skip(f, 1)

def skip_unsigned_char(f):
    skip(f, 1)

def skip_signed_short(f):
    skip(f, 2)

def skip_unsigned_int(f):
    skip(f, 4)

def skip_signed_int(f):
    skip(f, 4)

def skip_unsigned_long(f):
    skip(f, 8)

def skip_signed_long(f):
    skip(f, 8)

def skip_length_field(f):
    length = 0
    is_encoded = False
    _byte = read_unsigned_char(f)
    enc_type = (_byte & 0xC0) >> 6
    if enc_type == REDIS_RDB_14BITLEN:
        skip_unsigned_char(f)
    elif _byte == REDIS_RDB_32BITLEN:
        skip_unsigned_int(f)
    elif _byte == REDIS_RDB_64BITLEN:
        skip_unsigned_long(f)

def read_length_with_encoding(f):
    length = 0
    is_encoded = False
    bytes = []
    bytes.append(read_unsigned_char(f))
    enc_type = (bytes[0] & 0xC0) >> 6
    if enc_type == REDIS_RDB_ENCVAL:
        is_encoded = True
        length = bytes[0] & 0x3F
    elif enc_type == REDIS_RDB_6BITLEN:
        length = bytes[0] & 0x3F
    elif enc_type == REDIS_RDB_14BITLEN:
        bytes.append(read_unsigned_char(f))
        length = ((bytes[0] & 0x3F) << 8) | bytes[1]
    elif bytes[0] == REDIS_RDB_32BITLEN:
        length = read_unsigned_int_be(f)
    elif bytes[0] == REDIS_RDB_64BITLEN:
        length = read_unsigned_long_be(f)
    else:
        raise Exception('read_length_with_encoding', "Invalid string encoding %s (encoding byte 0x%X)" % (enc_type, bytes[0]))
    return (length, is_encoded)

def read_length(f) :
    return read_length_with_encoding(f)[0]

StringMetadata = namedtuple('StringMetadata', ['length', 'is_number', 'is_shared_number', 'is_compressed', 'compressed_length'])
def read_string_metadata(f):
    tup = read_length_with_encoding(f)
    length = tup[0]
    is_encoded = tup[1]
    is_number = False
    is_shared_number = False
    is_compressed = False
    compressed_length = 0

    if is_encoded:
        flag = length
        if flag == REDIS_RDB_ENC_INT8:
            is_number = True
            is_shared_number = True
            skip_signed_char(f)
        elif flag == REDIS_RDB_ENC_INT16:
            is_number = True
            _val = read_signed_short(f)
            is_shared_number = _val < REDIS_SHARED_INTEGERS
        elif flag == REDIS_RDB_ENC_INT32:
            is_number = True
            is_shared_number = False
            skip_signed_int(f)
        elif flag == REDIS_RDB_ENC_LZF:
            is_compressed = True
            compressed_length = read_length(f)
            length = read_length(f)
            skip(f, compressed_length)
    else:
        skip(f, length)

    return StringMetadata(length=length, 
                is_number=is_number, is_shared_number=is_shared_number,
                is_compressed=is_compressed, compressed_length=compressed_length)

def read_string(f) :
    tup = read_length_with_encoding(f)
    length = tup[0]
    is_encoded = tup[1]
    val = None
    if is_encoded :
        if length == REDIS_RDB_ENC_INT8 :
            val = read_signed_char(f)
        elif length == REDIS_RDB_ENC_INT16 :
            val = read_signed_short(f)
        elif length == REDIS_RDB_ENC_INT32 :
            val = read_signed_int(f)
        elif length == REDIS_RDB_ENC_LZF :
            clen = read_length(f)
            l = read_length(f)
            val = lzf_decompress(f.read(clen), l)
        else:
            raise Exception('read_string', "Invalid string encoding %s"%(length))
    else :
        val = f.read(length)
    return val

def read_float(f):
    dbl_length = read_unsigned_char(f)
    if dbl_length == 253:
        return float('nan')
    elif dbl_length == 254:
        return float('inf')
    elif dbl_length == 255:
        return float('-inf')
    data = f.read(dbl_length)
    if isinstance(data, str):
        return float(data)
    return data # bug?

def to_datetime(usecs_since_epoch):
    seconds_since_epoch = usecs_since_epoch // 1000000
    if seconds_since_epoch > 221925052800 :
        seconds_since_epoch = 221925052800
    useconds = usecs_since_epoch % 1000000
    dt = datetime.datetime.utcfromtimestamp(seconds_since_epoch)
    delta = datetime.timedelta(microseconds = useconds)
    return dt + delta
    
def read_signed_char(f) :
    return unpack('b', f.read(1))[0]
    
def read_unsigned_char(f) :
    return unpack('B', f.read(1))[0]

def read_signed_short(f) :
    return unpack('h', f.read(2))[0]
        
def read_unsigned_short(f) :
    return unpack('H', f.read(2))[0]

def read_signed_int(f) :
    return unpack('i', f.read(4))[0]
    
def read_unsigned_int(f) :
    return unpack('I', f.read(4))[0]

def read_unsigned_int_be(f):
    return unpack('>I', f.read(4))[0]

def read_24bit_signed_number(f):
    s = b'0' + f.read(3)
    num = unpack('i', s)[0]
    return num >> 8
    
def read_signed_long(f) :
    return unpack('q', f.read(8))[0]
    
def read_unsigned_long(f) :
    return unpack('Q', f.read(8))[0]
    
def read_unsigned_long_be(f) :
    return unpack('>Q', f.read(8))[0]

def read_double(f) :
    return unpack('d', f.read(8))[0]

def string_as_hexcode(string) :
    for s in string :
        if isinstance(s, int) :
            print(hex(s))
        else :
            print(hex(ord(s)))

if __name__ == '__main__':

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dumps_dir = os.path.join(base_dir, "tests", "dumps")
    for rdb in os.listdir(dumps_dir):
        if not rdb.endswith(".rdb"):
            continue
        with open(os.path.join(dumps_dir, rdb), "rb") as f:
            print("Processing file %s" % rdb)
            records = RedisMemoryAnalyzer().get_memory_records(f)
            for record in records:
                if record and record.encoding in ('hashtable') and record.type=='hash':
                    print(record)

