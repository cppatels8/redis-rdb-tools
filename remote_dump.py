import redis

def dict_merge(*dicts):
    merged = {}
    for d in dicts:
        merged.update(d)
    return merged


def parse_sync_response(*args):
    with open("remote_dump.rdb", "wb") as f:
        f.write(args[0])
    return None

class RedisWithSync(redis.StrictRedis):
    # Overridden callbacks
    RESPONSE_CALLBACKS = dict_merge(
        redis.StrictRedis.RESPONSE_CALLBACKS,
        {
            'SYNC': parse_sync_response,
        }
    )

    def sync(self):
        return self.execute_command('SYNC')


def download_dump(local_path, host, port, username=None, password=None):
    """
    Download a rdb dump file from a remote redis server
    local_path is the path where the rdb will be saved
    host, port, username and password are used 
    to connect to the remote redis server
    """
    remote_redis = RedisWithSync(host, port, username, password)
    print(remote_redis.sync())

if __name__ == '__main__':
    download_dump("dump.rdb", "localhost", 6379)