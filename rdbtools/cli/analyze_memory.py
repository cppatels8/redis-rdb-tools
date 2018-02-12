import ctypes
import json
import sys
import os

C_LIBRARY_PATH = os.getcwd() + "/librdb.so"
CSV_OUTPUT_PATH = os.getcwd() + "/dump.csv"
JSON_OUTPUT_PATH = os.getcwd() + "/dump.json"

# Compiled c code. To make this file run gcc -shared -o librdb.so -fPIC *.c
# Inside your native directory
rdblib = ctypes.CDLL(C_LIBRARY_PATH)

def memory_analyzer(snapshot_path):
    rdblib.rdbMemoryAnalysis(snapshot_path, CSV_OUTPUT_PATH, JSON_OUTPUT_PATH)
    data = json.load(open(JSON_OUTPUT_PATH))
    #TODO: Write logic to post data to rdbtools.com

if __name__ == '__main__':
    memory_analyzer(sys.argv[1])
