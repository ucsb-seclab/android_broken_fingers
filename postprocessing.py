#!/usr/bin/env python

import sys
import os
import json


def get_res(fp):
    cc = fp.read()
    try:
        rj = cc.split("================================= JSON START")[1].split("================================= JSON END")[0].strip()
    except IndexError:
        return None
    res = json.loads(rj)
    return res


def compute_outcome(res):
    features = res['features']
    fnames = [f['name'] for f in features]

    res = ""
    if "Authenticate" not in fnames or "Succeeded" not in fnames:
        res = "NOT_USED"

    elif "Keybuilder" not in fnames:
        res = "WEAK"

    elif all(["Unknown" in f['result'] or "Weak" in f['result'] for f in features if f['name'] == 'Succeeded']) or \
            all(["Unknown" in f['result'] or "Weak" in f['result'] for f in features if f['name'] == 'Authenticate']):
        res = "WEAK"

    elif any([f['result'] == "Asymm" for f in features if f['name'] == 'Keybuilder']) and \
            any([f['result'] == "Asymm" for f in features if f['name'] == 'Succeeded']):
        res = "SIGN"

    if res == "":
        res = "DECRYPTION"

    if "AuthenticationRequired" not in fnames or \
            any([f['value'] == "0" for f in features if f['name'] == 'AuthenticationRequired']):
        res = "WEAK"

    return res


def main(fname, fp):
    res = get_res(fp)
    if res is None:
        print "=" * 10, "FINAL_RESULT", fname, fname, os.path.basename(fname).replace(".apk", "").replace(".txt",""), "ERROR"
        return

    for f in res['features']:
        sslice = f['slice'].split("\n")[0]
        print "--->", res['meta']['pname'], f['name'], f['value'], f['result'], "location:", f['location'], "extra:", repr(f['extra']), "sslice:", sslice

    fres = compute_outcome(res)

    print res['meta']
    print "=" * 10, "FINAL_RESULT", fname, res['meta']['fname'], res['meta']['pname'], fres


if __name__ == "__main__":
    if sys.argv[1] == "-":
        main("stdin", sys.stdin)
    else:
        for fname in sys.argv[1:]:
            with open(fname) as fp:
                main(fname, fp)
