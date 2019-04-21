#!/usr/bin/python
import cgi, os
import sys
import ehc
import json


import cgitb; cgitb.enable()

try:
    post = str(sys.stdin.read())

    esaconfig = ""
    start = False
    for line in post.splitlines():
        if "<?xml" in line:
            start = True
        if start:
            esaconfig = esaconfig + line + '\n'
        if "</config>" in line:
            start = False
    ehc = ehc.EHC(esaconfig)
    ehc.get_licenses()
    ehc.check_rules()
    ehc.check_hat()
    tests = ehc.get_result()
    rsp = {"result":"OK"}
    rsp.update({"checks":tests})
except Exception as err:
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    estring = "{} {} {} {}".format(err,exc_type, fname, exc_tb.tb_lineno)
    rsp = {"result":"Error:" + estring}    

print("Content-type:application/json\n\n")
print json.dumps(rsp)



