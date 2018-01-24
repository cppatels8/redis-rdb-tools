from struct import pack, unpack
import io
import datetime
import re
import os

from iowrapper import IOWrapper

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

class RedisMemoryAnalyzer(object):
    """
    Provides a detailed breakup of memory used by a redis instance 
    
    """
    def __init__(self) :
        self.current_db = 0
        self.current_key = None
        self.has_expiry = None
        self.rdb_version = 0

    def analyze_redis_instance(self, host, port, password):
        pass

    def analyze_rdb(self, filename):
        """
        Parse a redis rdb dump file, and call methods in the 
        callback object during the parsing operation.
        """
        self.parse_fd(open(filename, "rb"))

    def parse_fd(self, fd):
        with fd as f:
            verify_magic_string(f.read(5))
            self.rdb_version = get_rdb_version(f.read(4))
            
            while True:
                self.has_expiry = False
                data_type = read_unsigned_char(f)

                if data_type == REDIS_RDB_OPCODE_EXPIRETIME_MS:
                    self.has_expiry = True
                    skip(f, 8)
                    data_type = read_unsigned_char(f)
                elif data_type == REDIS_RDB_OPCODE_EXPIRETIME:
                    self.has_expiry = True
                    skip(f, 4)
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
                        # f.read(8)
                        skip_checksum(f)
                    break

                self.current_key = read_string(f)
                #print(self.current_key)
                self.read_object(f, data_type)


    # Read an object for the stream
    # f is the redis file 
    # enc_type is the type of object
    def read_object(self, f, enc_type) :
        if enc_type == REDIS_RDB_TYPE_STRING:
            val = read_string(f)
            # self._callback.set(self._key, val, self._expiry, info={'encoding':'string'})
        elif enc_type == REDIS_RDB_TYPE_LIST:
            # A redis list is just a sequence of strings
            # We successively read strings from the stream and create a list from it
            # The lists are in order i.e. the first string is the head, 
            # and the last string is the tail of the list
            length = read_length(f)
            # self._callback.start_list(self._key, self._expiry, info={'encoding':'linkedlist' })
            for count in range(0, length):
                val = read_string(f)
                # self._callback.rpush(self._key, val)
            # self._callback.end_list(self._key, info={'encoding':'linkedlist' })
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
        elif enc_type == REDIS_RDB_TYPE_ZSET or enc_type == REDIS_RDB_TYPE_ZSET_2 :
            length = read_length(f)
            # self._callback.start_sorted_set(self._key, length, self._expiry, info={'encoding':'skiplist'})
            for count in range(0, length):
                val = read_string(f)
                score = read_double(f) if enc_type == REDIS_RDB_TYPE_ZSET_2 else read_float(f)
                # self._callback.zadd(self._key, score, val)
            # self._callback.end_sorted_set(self._key)
        elif enc_type == REDIS_RDB_TYPE_HASH:
            length = read_length(f)
            # self._callback.start_hash(self._key, length, self._expiry, info={'encoding':'hashtable'})
            for count in range(0, length):
                field = read_string(f)
                value = read_string(f)
                # self._callback.hset(self._key, field, value)
            # self._callback.end_hash(self._key)
        elif enc_type == REDIS_RDB_TYPE_HASH_ZIPMAP:
            self.read_zipmap(f)
        elif enc_type == REDIS_RDB_TYPE_LIST_ZIPLIST:
            self.read_ziplist(f)
        elif enc_type == REDIS_RDB_TYPE_SET_INTSET:
            self.read_intset(f)
        elif enc_type == REDIS_RDB_TYPE_ZSET_ZIPLIST:
            self.read_zset_from_ziplist(f)
        elif enc_type == REDIS_RDB_TYPE_HASH_ZIPLIST:
            self.read_hash_from_ziplist(f)
        elif enc_type == REDIS_RDB_TYPE_LIST_QUICKLIST:
            self.read_list_from_quicklist(f)
        elif enc_type == REDIS_RDB_TYPE_MODULE:
            raise Exception('read_object', 'Unable to read Redis Modules RDB objects (key %s)' % self._key)
        elif enc_type == REDIS_RDB_TYPE_MODULE_2:
            self.read_module(f)
        else:
            raise Exception('read_object', 'Invalid object type %d for key %s' % (enc_type, self._key))

    def read_intset(self, f) :
        raw_string = read_string(f)
        buff = BytesIO(raw_string)
        encoding = read_unsigned_int(buff)
        num_entries = read_unsigned_int(buff)
        # self._callback.start_set(self._key, num_entries, self._expiry, info={'encoding':'intset', 'sizeof_value':len(raw_string)})
        for x in range(0, num_entries) :
            if encoding == 8 :
                entry = read_signed_long(buff)
            elif encoding == 4 :
                entry = read_signed_int(buff)
            elif encoding == 2 :
                entry = read_signed_short(buff)
            else :
                raise Exception('read_intset', 'Invalid encoding %d for key %s' % (encoding, self._key))
            # self._callback.sadd(self._key, entry)
        # self._callback.end_set(self._key)

    def read_ziplist(self, f):
        raw_string = self.read_string(f)
        buff = BytesIO(raw_string)
        zlbytes = read_unsigned_int(buff)
        tail_offset = read_unsigned_int(buff)
        num_entries = read_unsigned_short(buff)
        # self._callback.start_list(self._key, self._expiry, info={'encoding':'ziplist', 'sizeof_value':len(raw_string)})
        for x in range(0, num_entries):
            val = self.read_ziplist_entry(buff)
            # self._callback.rpush(self._key, val)

        zlist_end = read_unsigned_char(buff)
        if zlist_end != 255 : 
            raise Exception('read_ziplist', "Invalid zip list end - %d for key %s" % (zlist_end, self._key))
        # self._callback.end_list(self._key, info={'encoding':'ziplist'})

    def read_list_from_quicklist(self, f):
        count = read_length(f)
        total_size = 0
        # self._callback.start_list(self._key, self._expiry, info={'encoding': 'quicklist', 'zips': count})
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

    def read_zset_from_ziplist(self, f) :
        raw_string = read_string(f)
        buff = BytesIO(raw_string)
        zlbytes = read_unsigned_int(buff)
        tail_offset = read_unsigned_int(buff)
        num_entries = read_unsigned_short(buff)
        if (num_entries % 2) :
            raise Exception('read_zset_from_ziplist', "Expected even number of elements, but found %d for key %s" % (num_entries, self._key))
        num_entries = num_entries // 2
        # self._callback.start_sorted_set(self._key, num_entries, self._expiry, info={'encoding':'ziplist', 'sizeof_value':len(raw_string)})
        for x in range(0, num_entries) :
            member = self.read_ziplist_entry(buff)
            score = self.read_ziplist_entry(buff)
            if isinstance(score, bytes) :
                score = float(score)
            # self._callback.zadd(self._key, score, member)
        zlist_end = read_unsigned_char(buff)
        if zlist_end != 255 : 
            raise Exception('read_zset_from_ziplist', "Invalid zip list end - %d for key %s" % (zlist_end, self._key))
        # self._callback.end_sorted_set(self._key)

    def read_hash_from_ziplist(self, f) :
        raw_string = read_string(f)
        buff = BytesIO(raw_string)
        zlbytes = read_unsigned_int(buff)
        tail_offset = read_unsigned_int(buff)
        num_entries = read_unsigned_short(buff)
        if (num_entries % 2) :
            raise Exception('read_hash_from_ziplist', "Expected even number of elements, but found %d for key %s" % (num_entries, self._key))
        num_entries = num_entries // 2
        # self._callback.start_hash(self._key, num_entries, self._expiry, info={'encoding':'ziplist', 'sizeof_value':len(raw_string)})
        for x in range(0, num_entries) :
            field = self.read_ziplist_entry(buff)
            value = self.read_ziplist_entry(buff)
            # self._callback.hset(self._key, field, value)
        zlist_end = read_unsigned_char(buff)
        if zlist_end != 255 : 
            raise Exception('read_hash_from_ziplist', "Invalid zip list end - %d for key %s" % (zlist_end, self._key))
        # self._callback.end_hash(self._key)
    
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
        raw_string = self.read_string(f)
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
        length, encoding = self.read_length_with_encoding(iowrapper)
        record_buffer = self._callback.start_module(self._key, _decode_module_id(length), self._expiry)

        if not record_buffer:
            iowrapper.stop_recording()

        opcode = self.read_length(iowrapper)
        while opcode != REDIS_RDB_MODULE_OPCODE_EOF:
            if opcode == REDIS_RDB_MODULE_OPCODE_SINT or opcode == REDIS_RDB_MODULE_OPCODE_UINT:
                data = self.read_length(iowrapper)
            elif opcode == REDIS_RDB_MODULE_OPCODE_FLOAT:
                data = self.read_float(iowrapper)
            elif opcode == REDIS_RDB_MODULE_OPCODE_DOUBLE:
                data = read_double(iowrapper)
            elif opcode == REDIS_RDB_MODULE_OPCODE_STRING:
                data = self.read_string(iowrapper)
            else:
                raise Exception("Unknown module opcode %s" % opcode)
            self._callback.handle_module_data(self._key, opcode, data)
            # read the next item in the module data type
            opcode = self.read_length(iowrapper)

        buffer = None
        if record_buffer:
            # prepand the buffer with REDIS_RDB_TYPE_MODULE_2 type
            buffer = pack('B', REDIS_RDB_TYPE_MODULE_2) + iowrapper.get_recorded_buffer()
            iowrapper.stop_recording()
        self._callback.end_module(self._key, buffer_size=iowrapper.get_recorded_size(), buffer=buffer)

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

def skip_unsigned_char(f):
    skip(f, 1)

def skip_unsigned_int(f):
    skip(f, 4)

def skip_unsigned_long(f):
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

def read_float(self, f):
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
    RedisMemoryAnalyzer().analyze_rdb("/Users/sripathikrishnan/apps/redis-dumps/datascience_se.rdb")