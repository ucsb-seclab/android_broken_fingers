#!/usr/bin/env python

import os
import contextlib
import tempfile
import shutil
import subprocess
import time
import sys


self_dir = os.path.dirname(os.path.realpath(__file__))


@contextlib.contextmanager
def _tempdir(prefix='/tmp/pysoot_tmp', delete=True):
    tmpdir = tempfile.mkdtemp(prefix=prefix)
    try:
        yield tmpdir
    finally:
        if delete:
            shutil.rmtree(tmpdir)


def exec_cmd(args, cwd=None, shell=False, debug=False):
    # debug = True
    if debug:
        print "EXECUTING:", repr(args), cwd, shell

    pipe = subprocess.PIPE
    p = subprocess.Popen(args, cwd=cwd, shell=shell, stdout=pipe, stderr=pipe)
    std = p.communicate()
    retcode = p.poll()
    res = (std[0], std[1], retcode)

    if debug:
        print "RESULT:", repr(res)

    return res


if __name__ == "__main__":
    out_path = os.path.join(self_dir, "SootAnalysis.jar")
    soot_jar = os.path.join(self_dir, "soot-trunk.jar")
    json_jar = os.path.join(self_dir, "gson-2.6.2.jar")
    libs = [soot_jar,json_jar]
    java_code = self_dir

    try:
        os.unlink(out_path)
    except OSError:
        pass

    print "*** Compiling..."
    with _tempdir() as td:
        jar_dir = os.path.join(td, "jar")
        os.mkdir(jar_dir)

        res = exec_cmd(["javac -d " + jar_dir + " -cp " + ":".join(libs) + " $(find src -name '*.java')"], shell=True,
                 cwd=java_code)
        if res[2] != 0:
            print res[0]
            print ""
            print res[1]
            sys.exit(1)

        # I hate Java, try to do this with Maven
        for lib in libs:
            exec_cmd(["jar", "-xf", lib], cwd=jar_dir)

        exec_cmd(["jar cvfm ../out.jar %s **" % os.path.join(java_code, "META-INF", "MANIFEST.MF")], cwd=jar_dir, shell=True)
        shutil.copy2(os.path.join(td, "out.jar"), out_path)

    print "*** Compilation done!"

