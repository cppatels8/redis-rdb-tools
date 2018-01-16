from redis.connection import Connection

def download_rdb(out_file, host='localhost', port=6379, password=None):
    """
    Download a rdb dump file from a remote redis server
    out_file is the file name where the rdb will be saved
    host, port, password are used to connect to the remote redis server
    """
    try:
        conn = _MyConnection(host=host, port=port, password=password)
        conn.send_command("sync")

        with open(out_file, "wb") as out:
            conn.read_file(out)
    finally:
        conn.disconnect()

class _MyConnection(Connection):
    def read_file(self, out):
        rdb_length = self.read_rdb_length()

        buff_length = 16384
        remaining = rdb_length
        while(remaining > 0):
            partial = self._sock.recv(min(buff_length, remaining))
            remaining = remaining - len(partial)
            out.write(partial)

    def read_rdb_length(self):
        # Read till we encounter \n in the socket
        data = b''.join(iter(lambda: self._sock.recv(1), b'\n'))
        # The first character is the $ symbol, skip it
        # Everything after that is the length of the file
        length = int(data[1:])
        return length

if __name__ == '__main__':
    download_rdb("dump.rdb")