import requests
import ctypes
import json
import gzip
import os
import sys
import uuid

C_LIBRARY_PATH = os.getcwd() + "/librdb.so"
CSV_OUTPUT_PATH = os.getcwd() + "/dump.csv"
GZIP_OUTPUT_PATH = os.getcwd() + "/dump.gz"
JSON_OUTPUT_PATH = os.getcwd() + "/dump.json"
APP_ENDPOINT = "http://127.0.0.1:8000"
AWS_S3_ENDPOINT = "https://rdbtools-dev.s3.amazonaws.com/"
SNAPSHOT_SUMMARY_ENDPOINT = APP_ENDPOINT + "/api/snapshot/{}/summary/"
UPLOAD_CSV_ENDPOINT = APP_ENDPOINT + "/api/upload-info/?sanpshot_id={}&only_signed_url=true&filepath={}"


# Compiled c code. To make this file run gcc -shared -o librdb.so -fPIC *.c
# Inside your native directory
rdblib = ctypes.CDLL(C_LIBRARY_PATH)


def memory_analyzer(snapshot_path):
    sanpshot_id = str(uuid.uuid4())

    if not _is_snapshot_path_valid(snapshot_path):
        raise Exception("Snapshot path not valid.")

    # Does Memory analysis and returns summary of RDB snapshot
    print "Processing rdb snapshot ......."
    summary = analyze_rdb(snapshot_path)
    print "Done.\n"
    
    
 
    # Sends Summary data of snapshot to app.rdbtools.com
    print "Sending sanpshot summary to rdbtools.com ......."
    summary["snapshotId"] = sanpshot_id
    headers = {'content-type': 'application/json'}
    resp = request_client("post", SNAPSHOT_SUMMARY_ENDPOINT.format(sanpshot_id), data=json.dumps(summary), headers=headers)
    print "Done.\n"
  
    # gzip the csv output file
    gzip_csv_file()
  
    # Get s3 signed URL
    print "Uploading snapshot csv file to rdbtools.com ......."
    resp = request_client("get", UPLOAD_CSV_ENDPOINT.format(sanpshot_id, GZIP_OUTPUT_PATH))
    data = resp.json()

    # uploads file to s3
    upload_file_to_s3(data)
    print "Done.\n"


def gzip_csv_file():
    # Compresses the CSV output file to gzip format
    with open(CSV_OUTPUT_PATH, "rb") as file_in:
        with gzip.open(GZIP_OUTPUT_PATH, "wb") as file_out:
            file_out.writelines(file_in)


def upload_file_to_s3(data):
    files = {"file": open(CSV_OUTPUT_PATH, 'rb').read()}
    return request_client("post", AWS_S3_ENDPOINT, data=data["fields"], files=files)


def _is_snapshot_path_valid(path):
    # validates if snapshot exists at the given path or not
    return os.path.exists(path)


def analyze_rdb(snapshot_path):
    rdblib.rdbMemoryAnalysis(snapshot_path, CSV_OUTPUT_PATH, JSON_OUTPUT_PATH)
    return json.load(open(JSON_OUTPUT_PATH))


def request_client(method, url, data=None, headers=None, files=None):
    resp = requests.request(method, url,
                            headers=headers,
                             data=data, files=files)

    if resp.status_code >= 200 and resp.status_code <= 299:
        return resp
    else:
        raise Exception("Some error occurred.")


if __name__ == '__main__':
    # It takes one argument path of your snapshot
    memory_analyzer(sys.argv[1])

