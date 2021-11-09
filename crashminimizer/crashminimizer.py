#!/usr/bin/env python3

# Author: Casper
# Email: slei.casper@gmail.com

import re
import sys
import time
import argparse
import os
import random
import psutil
import pty
import multiprocessing

DEBUG = True
STACKTRACELEVEL = 3

report_fd = None
def print_red(aMsg):
    global report_fd
    if report_fd:
        report_fd.write(aMsg.encode('latin-1') + b'\n')
    print("\033[31m%s\033[0m"%aMsg)
def print_green(aMsg):
    global report_fd
    if report_fd:
        report_fd.write(aMsg.encode('latin-1') + b'\n')
    print("\033[32m%s\033[0m"%aMsg)
def print_yellow(aMsg, aEnd = '\n'):
    global report_fd
    if report_fd:
        report_fd.write(aMsg.encode('latin-1') + b'\n')
    print("\033[33m%s\033[0m"%(aMsg), end = aEnd, flush=True)
def print_plain(aMsg):
    global report_fd
    if report_fd:
        report_fd.write(aMsg.encode('latin-1') + b'\n')
    print(aMsg)


def loginfo(aMsg):
    print_green(aMsg)

def logwarn(aMsg):
    print_yellow(aMsg)

def logerror(aMsg):
    print_red(aMsg)
    exit(1)

def genrandomname(aLen = 10):
    res = ''
    for i in range(aLen):
        res += random.choice('qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM')
    return res

gdbscripttemplate = '''
import gdb
inf = gdb.inferiors()[0]
gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set logging file /tmp/TEMPFILENAMEcrashanalysis.txt")
gdb.execute("set logging overwrite on")
gdb.execute("set logging on")
gdb.execute("set follow-fork-mode parent")
gdb.execute("set logging redirect on")
gdb.execute("file TARGETBINARYPATH")
gdb.execute("r PROGRAMARGUMENTS 2>/dev/null 1>/dev/null")
gdb.execute("set logging file /tmp/TEMPFILENAMEcrashanalysis.txt")
gdb.execute("set logging on")
gdb.execute("set logging redirect on")
if inf.threads() != ():
    print("----------------------------------------------------------------------")
    gdb.execute("bt 100")
    print("----------------------------------------------------------------------")
    gdb.execute("i proc mappings")
    print("----------------------------------------------------------------------")
stacktracefd = open("/tmp/TEMPFILENAMEstacktrace.txt", "wb")
tframe = gdb.newest_frame()
tidx = 0
while tframe != None:
    taddr = tframe.pc()
    tname = str(tframe.name())
    stacktracefd.write("{0:d}:::::0x{1:x}:::::{2:s}\\n".format(tidx, taddr, tname).encode('ascii'))
    tframe = tframe.older()
    tidx += 1
stacktracefd.close()
gdb.execute("q")
'''

split_label = '----------------------------------------------------------------------\n'

bt_pn = re.compile(r'#([0-9a-f]+)\s*(0x[0-9a-f]+)?\s*(in)?\s*([\w_]+)\s*')
segvaddr_pn = re.compile(r'SEGV on unknown address (0x[0-9a-f]+)')
stopreason_pn = re.compile(r'Program received signal (.*),')
blackkeywordlist = [
        'sanitizer',
        'asan',
        '__GI_abort',
        '__GI_raise',
        '~ScopedInErrorReport',
        'ReportGenericError',
        '__assert_fail_base',
        '__GI___assert_fail'
        ]


class CrashMinimizer():
    def __init__(self, aReportDir):
        global report_fd
        if aReportDir:
            if os.path.exists(aReportDir):
                logerror("found crash report directory: %s, delete it if you want to continue"%aReportDir)
            os.mkdir(aReportDir)
            self.reportdir = aReportDir
            report_fd.close()
            os.unlink('report.txt')
            report_fd = open("%s/report.txt"%self.reportdir, "wb")
        else:
            self.reportdir = None
        self.alluniqstacktraces = {
                'normal': [],
                'SEGV': [],
                'heap-buffer-overflow': [],
                'stack-overflow': [],
                'stack-underflow': [],
                'stack-buffer-overflow': [],
                'heap-use-after-free': [],
                'global-buffer-overflow': [],
                'stack-use-after-return': [],
                'stack-use-after-scope': [],
                'initialization-order-fiasco': [],
                'negative-size-param': [],
                'big-malloc-size': [],
                'memcpy-param-overlap': [],
                'oom': [],
                'FPE': [],
                'invalidfree': [],
                'use-after-poison': [],
                'double-free': [],
                'unknown-crash': [],
                }
        self.timeoutlist = []
        self.abnormallist = []
        self.uniqnum = 0

    def cleanuptmpfiles(self, aTempName):
        if os.path.exists(f"/tmp/{aTempName}gdbscript.py"):
            os.unlink(f"/tmp/{aTempName}gdbscript.py")
        if os.path.exists(f"/tmp/{aTempName}stdout.txt"):
            os.unlink(f"/tmp/{aTempName}stdout.txt")
        if os.path.exists(f"/tmp/{aTempName}stderr.txt"):
            os.unlink(f"/tmp/{aTempName}stderr.txt")
        if os.path.exists(f"/tmp/{aTempName}gdbstdout.txt"):
            os.unlink(f"/tmp/{aTempName}gdbstdout.txt")
        if os.path.exists(f"/tmp/{aTempName}gdbstderr.txt"):
            os.unlink(f"/tmp/{aTempName}gdbstderr.txt")
        if os.path.exists(f"/tmp/{aTempName}crashanalysis.txt"):
            os.unlink(f"/tmp/{aTempName}crashanalysis.txt")
        if os.path.exists(f"/tmp/{aTempName}stacktrace.txt"):
            os.unlink(f"/tmp/{aTempName}stacktrace.txt")

    def runpoconce(self, aTargetBinPath, aFuzzArgs, aPocPath, aTestCasePath, aSlaveTTY=None):
        '''
        this function is multi-process safe, you can run it in multiple processes
        return an object describing stack trace
        '''
        aPocPath = aPocPath.replace('(', '\\(').replace(')', '\\)')
        tempname = genrandomname()
        newargs = []
        isstdin = True
        for iarg in aFuzzArgs:
            if '@@' in iarg:
                isstdin = False
                if aTestCasePath == None:
                    newargs.append(iarg.replace('@@', "%s"%aPocPath))
                else:
                    newargs.append(iarg.replace('@@', "%s"%aTestCasePath))
            else:
                newargs.append(iarg)
        if aTestCasePath:
            with open(aPocPath, 'rb') as f:
                crashdata = f.read()
            with open(aTestCasePath, 'wb') as f:
                f.write(crashdata)
        tpid = os.fork()
        istimeout = False
        if tpid == 0:
            os.environ['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=0'
            tnewstdout = os.open(f'/tmp/{tempname}stdout.txt', os.O_RDWR|os.O_CREAT)
            if tnewstdout < 0:
                raise Exception("open failed")
            tnewstderr = os.open(f'/tmp/{tempname}stderr.txt', os.O_RDWR|os.O_CREAT)
            if tnewstderr < 0:
                raise Exception("open failed")
            if isstdin:
                tnewstdin = os.open(aPocPath, os.O_RDONLY)
                if tnewstdin < 0:
                    raise Exception("open failed")
                os.dup2(tnewstdin, 0)
            os.dup2(tnewstdout, 1)
            os.dup2(tnewstderr, 2)
            os.execvp(aTargetBinPath, [aTargetBinPath] + newargs)
        elif tpid > 0:
            tacc = 0
            while True:
                time.sleep(0.2)
                (retpid, retstatus) = os.waitpid(tpid, os.WNOHANG)
                if retpid == 0:
                    time.sleep(1)
                    tacc += 1
                    if tacc == 10:
                        os.system("rkill %d 2>&1 1>/dev/null"%tpid)
                        (retpid, retstatus) = os.waitpid(tpid, 0)
                        assert(retpid == tpid)
                        istimeout = True
                else:
                    break
        else:
            raise Exception("fork error")
        if istimeout == True:
            logwarn("timeout when testing poc, sig = %d"%os.WTERMSIG(retstatus));
            self.cleanuptmpfiles(tempname)
            return {
                    'result': 'timeout',
                    'pocpath': aPocPath,
                    }
        progstderrcont = open(f"/tmp/{tempname}stderr.txt", "rb").read().decode('latin-1')
        progstdoutcont = open(f"/tmp/{tempname}stdout.txt", "rb").read().decode('latin-1')
        gdbscript = gdbscripttemplate.replace("TARGETBINARYPATH", aTargetBinPath)
        if isstdin:
            newargs.append("<")
            newargs.append(aPocPath)
        gdbscript = gdbscript.replace("PROGRAMARGUMENTS", ' '.join(newargs))
        gdbscript = gdbscript.replace("TEMPFILENAME", tempname)
        open(f"/tmp/{tempname}gdbscript.py", "wb").write(gdbscript.encode('latin-1'))
        tpid = os.fork()
        if tpid == 0:
            os.environ['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=0'
            tnewstdout = os.open(f'/tmp/{tempname}gdbstdout.txt', os.O_RDWR|os.O_CREAT)
            if tnewstdout < 0:
                raise Exception("open failed")
            tnewstderr = os.open(f'/tmp/{tempname}gdbstderr.txt', os.O_RDWR|os.O_CREAT)
            if tnewstderr < 0:
                raise Exception("open failed")
            os.dup2(tnewstdout, 1)
            os.dup2(tnewstderr, 2)
            if aSlaveTTY:
                args = ["gdb", "--tty=%s"%(os.ttyname(aSlaveTTY)), "-nx", "-x", f"/tmp/{tempname}gdbscript.py"]
            else:
                args = ["gdb", "-nx", "-x", f"/tmp/{tempname}gdbscript.py"]
            os.execvp("gdb", args)
        elif tpid > 0:
            tacc = 0
            while True:
                time.sleep(0.5)
                (retpid, retstatus) = os.waitpid(tpid, os.WNOHANG)
                if retpid == 0:
                    time.sleep(1)
                    tacc += 1
                    if tacc == 10:
                        os.system("rkill %d 2>&1 1>/dev/null"%tpid)
                        (retpid, retstatus) = os.waitpid(tpid, 0)
                        assert(retpid == tpid)
                        break
                else:
                    break
        else:
            raise Exception("fork error")
        if os.WIFEXITED(retstatus) and os.WEXITSTATUS(retstatus) != 0:
            logerror("debug me")
        if os.WIFSIGNALED(retstatus):
            logwarn("timeout when testing poc, sig = %d"%os.WTERMSIG(retstatus));
            self.cleanuptmpfiles(tempname)
            return {
                    'result': 'timeout',
                    'pocpath': aPocPath,
                    }

        gdbstdout = open(f"/tmp/{tempname}gdbstdout.txt", "rb").read().decode('latin-1')
        gdbstderr = open(f"/tmp/{tempname}gdbstderr.txt", "rb").read().decode('latin-1')
        gdblog_text = open(f"/tmp/{tempname}crashanalysis.txt", "rb").read().decode('latin-1')
        stacktracelog = open(f"/tmp/{tempname}stacktrace.txt", "rb").read().decode('latin-1')
        gdblog = gdblog_text.split(split_label)[1:-1]
        if len(gdblog) == 0:
            self.cleanuptmpfiles(tempname)
            return {
                    'result': 'abnormal',
                    'pocpath': aPocPath,
                    }
        backtrace = gdblog[0].strip()
        vmmap = gdblog[1].strip()
        vmmap = vmmap.split('\n')
        allmaps = []
        startfound = False
        for mapline in vmmap:
            if startfound:
                allmaps.append(mapline.strip())
            else:
                if 'Start Addr' in mapline:
                    startfound = True

        alllibs = {}
        for mapline in allmaps:
            if len(mapline.split()) != 5:
                continue
            startaddr = int(mapline.split()[0], 16)
            endaddr = int(mapline.split()[1], 16)
            libname = mapline.split()[-1]
            if libname not in alllibs:
                alllibs[libname] = {'startaddr':startaddr, 'endaddr':endaddr}
            else:
                if alllibs[libname]['endaddr'] < endaddr:
                    alllibs[libname]['endaddr'] = endaddr
                if alllibs[libname]['startaddr'] > startaddr:
                    alllibs[libname]['startaddr'] = startaddr

        tcurrtrace = {
                'result': 'crash',
                'funcnames': [],
                'idxs': [],
                'addrs': [],
                'offs': [],
                'libs': [],
                'filenames': [],
                'pocfilename': aPocPath,
                'stopreason': '',
                'vultype': None,
                'progstdoutcont': progstdoutcont,
                'progstderrcont': progstderrcont,
                'gdbstdout': gdbstdout,
                'gdbstderr': gdbstderr,
                'gdblog_text': gdblog_text,
                'pocpath': aPocPath,
                }
        top100stackframes = stacktracelog.split('\n')[:100]
        for ibtline in top100stackframes:
            ibtline = ibtline.strip()
            if len(ibtline) == 0:
                continue
            (tidx, taddr, tname) = ibtline.split(':::::', 3)
            tidx = int(tidx)
            taddr = int(taddr, 16)
            contflag = False
            for bword in blackkeywordlist:
                if bword in tname:
                    contflag = True
                    break
            if contflag:
                continue
            libname = ''
            for ilibname in alllibs:
                tlib = alllibs[ilibname]
                if tlib['startaddr'] <= taddr and taddr < tlib['endaddr']:
                    libname = ilibname
                    imageoff = taddr - tlib['startaddr']
                    break
            if libname == '':
                logwarn("could not find lib of address 0x%x"%taddr)
            else:
                libname = ''

            tfilename = ''
            for tline in backtrace.split('\n'):
                tbtpnres = bt_pn.findall(tline)
                if len(tbtpnres) == 0:
                    continue
                if int(tbtpnres[0][0]) == tidx:
                    if ' at ' in tline:
                        tfilename = tline[tline.find(' at ') + 4:]
                    break

            tcurrtrace['funcnames'].append(tname)
            tcurrtrace['offs'].append(imageoff)
            tcurrtrace['libs'].append(libname)
            tcurrtrace['idxs'].append(tidx)
            tcurrtrace['addrs'].append(taddr)
            tcurrtrace['filenames'].append(tfilename)
            tcurrtrace['type'] = 'none'
            if tname in ['main', '__libc_start_main', '_start']:
                break
        self.cleanuptmpfiles(tempname)
        return tcurrtrace

    def checkunique(self, aStackTraceObj, aCallbackFunc = None):
        global STACKTRACELEVEL
        if aStackTraceObj['result'] == 'timeout':
            if aStackTraceObj['pocpath'] not in self.timeoutlist:
                self.timeoutlist.append(aStackTraceObj['pocpath'])
            return
        if aStackTraceObj['result'] == 'abnormal':
            if aStackTraceObj['pocpath'] not in self.abnormallist:
                self.abnormallist.append(aStackTraceObj['pocpath'])
            return
        find_in_one_of_these = False
        if 'AddressSanitizer' in aStackTraceObj['progstderrcont']:
            if 'heap-buffer-overflow' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['heap-buffer-overflow']
                aStackTraceObj['vultype'] = 'heap-buffer-overflow'
            elif 'stack-overflow' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['stack-overflow']
                aStackTraceObj['vultype'] = 'stack-overflow'
            elif 'stack-buffer-underflow' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['stack-underflow']
                aStackTraceObj['vultype'] = 'stack-buffer-underflow'
            elif 'stack-buffer-overflow' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['stack-buffer-overflow']
                aStackTraceObj['vultype'] = 'stack-buffer-overflow'
            elif 'heap-use-after-free' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['heap-use-after-free']
                aStackTraceObj['vultype'] = 'heap-use-after-free'
            elif 'global-buffer-overflow' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['global-buffer-overflow']
                aStackTraceObj['vultype'] = 'global-buffer-overflow'
            elif 'stack-use-after-return' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['stack-use-after-return']
                aStackTraceObj['vultype'] = 'stack-use-after-return'
            elif 'stack-use-after-scope' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['stack-use-after-scope']
                aStackTraceObj['vultype'] = 'stack-use-after-scope'
            elif 'initialization-order-fiasco' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['initialization-order-fiasco']
                aStackTraceObj['vultype'] = 'initialization-order-fiasco'
            elif 'negative-size-param' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['negative-size-param']
                aStackTraceObj['vultype'] = 'negative-size-param'
            elif ('AddressSanitizer: requested allocation size' in aStackTraceObj['progstderrcont']
                or 'AddressSanitizer failed to allocate' in aStackTraceObj['progstderrcont']):
                tuniqstacktraces = self.alluniqstacktraces['big-malloc-size']
                aStackTraceObj['vultype'] = 'big-malloc-size'
            elif 'memcpy-param-overlap' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['memcpy-param-overlap']
                aStackTraceObj['vultype'] = 'memcpy-param-overlap'
            elif 'allocator is out of memory' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['oom']
                aStackTraceObj['vultype'] = 'oom'
            elif 'FPE' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['FPE']
                aStackTraceObj['vultype'] = 'FPE'
            elif 'attempting free on address which was not malloc' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['invalidfree']
                aStackTraceObj['vultype'] = 'invalidfree'
            elif 'use-after-poison' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['use-after-poison']
                aStackTraceObj['vultype'] = 'use-after-poison'
            elif 'double-free' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['double-free']
                aStackTraceObj['vultype'] = 'double-free'
            elif 'unknown-crash' in aStackTraceObj['progstderrcont']:
                tuniqstacktraces = self.alluniqstacktraces['unknown-crash']
                aStackTraceObj['vultype'] = 'unknown-crash'
            elif 'SEGV' in aStackTraceObj['progstderrcont']:
                aStackTraceObj['vultype'] = 'SEGV'
                tuniqstacktraces = self.alluniqstacktraces['SEGV']
                tres = segvaddr_pn.findall(aStackTraceObj['progstderrcont'])
                if len(tres) > 0:
                    tres = tres[0]
                    if int(tres, 16) == 0:
                        aStackTraceObj['stopreason'] = 'null pointer dereference'
                    else:
                        aStackTraceObj['stopreason'] = 'crashed on address ' + tres
            else:
                logerror("unknown address sanitizer type, pls update !!! \n" + aStackTraceObj['progstderrcont'])
        else:
            if len(stopreason_pn.findall(aStackTraceObj['gdbstdout'])) != 0:
                aStackTraceObj['stopreason'] = stopreason_pn.findall(aStackTraceObj['gdbstdout'])[0]
            aStackTraceObj['vultype'] = 'normal'
            tuniqstacktraces = self.alluniqstacktraces['normal']
        aStackTraceObj['vulclass'] = tuniqstacktraces
        for oldtrace in aStackTraceObj['vulclass']:
            allequalflag = True
            for idx in range(min(STACKTRACELEVEL, min(len(oldtrace['offs']), len(aStackTraceObj['offs'])))):
                if aStackTraceObj['filenames'][idx] == "" and oldtrace['filenames'][idx] == "":
                    if aStackTraceObj['addrs'][idx] == oldtrace['addrs'][idx]:
                        continue
                elif aStackTraceObj['filenames'][idx] == oldtrace['filenames'][idx]:
                    continue
                allequalflag = False
                break
            if allequalflag == True:
                find_in_one_of_these = True
                break

        if find_in_one_of_these == False:
            loginfo("[+] found uniq backtrace %s"%aStackTraceObj['pocpath'])
            aStackTraceObj['vulclass'].append(aStackTraceObj)
            if aCallbackFunc:
                aCallbackFunc(aStackTraceObj)
            self.uniqnum += 1

    def printresult(self, aTotalCrashCount):
        loginfo("[+] all uniq crashes:")
        loginfo("%-30s%-40s%s"%("[vul type]", "[stop reason]", "[crash file name]"))
        count = 0
        for ivultypename in self.alluniqstacktraces:
            iuniqstacktraces = self.alluniqstacktraces[ivultypename]
            for iuniqstacktrace in iuniqstacktraces:
                tstopreason = iuniqstacktrace['stopreason']
                if self.reportdir:
                    uniqdirname = "%s/%d"%(self.reportdir, count)
                    os.mkdir(uniqdirname)
                    with open("%s/gdblog.txt"%uniqdirname, "wb") as ff:
                        ff.write(iuniqstacktrace['gdblog_text'].encode('latin-1'))
                    with open("%s/stdout.txt"%uniqdirname, "wb") as ff:
                        ff.write(iuniqstacktrace['progstdoutcont'].encode('latin-1'))
                    with open("%s/stderr.txt"%uniqdirname, "wb") as ff:
                        ff.write(iuniqstacktrace['progstderrcont'].encode('latin-1'))
                    pocbytes = open(iuniqstacktrace['pocpath'], 'rb').read()
                    with open("%s/%s"%(uniqdirname, os.path.basename(iuniqstacktrace['pocpath'])), "wb") as ff:
                        ff.write(pocbytes)
                print_red("%-30s%-40s%s"%(
                    ivultypename,
                    tstopreason,
                    iuniqstacktrace['pocfilename']))
                for i in range(len(iuniqstacktrace['funcnames'])):
                    shortnameres = []
                    tlen = 0
                    for iword in iuniqstacktrace['filenames'][i].split('/')[::-1]:
                        tlen += len(iword)
                        shortnameres.append(iword)
                        if tlen > 100:
                            break
                    shortnameres = '/'.join(shortnameres[::-1])
                    if len(shortnameres) > 50:
                        shortnameres = shortnameres[-50:]
                    print_plain("\t%-5d0x%016x %-30s %s"%(
                        iuniqstacktrace['idxs'][i],
                        iuniqstacktrace['addrs'][i],
                        iuniqstacktrace['funcnames'][i],
                        shortnameres,
                        ))
                count += 1
        for iname in self.timeoutlist:
            logwarn("[+] timeout: %s"%iname)
        for iname in self.abnormallist:
            logwarn("[+] abnormal: %s"%iname)
        loginfo("[+] total crash count = %d"%(aTotalCrashCount))
        loginfo("[+] total uniq crash count = %d"%self.uniqnum)
        if self.reportdir:
            loginfo("[+] report is saved to %s"%self.reportdir)
        else:
            loginfo("[+] report is saved to report.txt")

def main():
    global report_fd, STACKTRACELEVEL
    report_fd = open("report.txt", "wb")
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--crashdir", required = True, help = "crash directory")
    parser.add_argument("-w", "--writepath", help = "test case writing path")
    parser.add_argument("-s", "--suffix", help = "test case suffix")
    parser.add_argument("-d", "--comparisondepth", type = int, default = 3, help = "comparison stack depth")
    parser.add_argument('rest', nargs=argparse.REMAINDER, help = "tested program arguments")
    parsed_args = parser.parse_args()
    crashdir = parsed_args.crashdir
    STACKTRACELEVEL = parsed_args.comparisondepth
    if crashdir[-1] != '/':
        crashdir += '/'
    testcasewritepath = parsed_args.writepath
    suffix = parsed_args.suffix
    targetbinpath = parsed_args.rest[0]
    fuzzargs = parsed_args.rest[1:]
    if not os.path.exists(targetbinpath):
        logerror("couldn't find target binary")

    if testcasewritepath and suffix:
        logerror("you can only set 'testwritepath' or 'suffix'")

    progname = os.path.basename(targetbinpath)
    assert(len(progname) != 0)
    minimizer = CrashMinimizer("%s_crashreport"%progname)

    crashfiles = os.listdir(crashdir)
    crashfiles = [x for x in crashfiles if x not in ['README.txt']]
    crashfiles.sort()
    print_green("starting minimize %d crashes"%len(crashfiles))
    if testcasewritepath == None:
        pcount = int(multiprocessing.cpu_count() * (1 - psutil.cpu_percent()*0.01) * 2)
        if pcount < 3:
            pcount = 3
    else:
        pcount = 1

    allcrashresults = multiprocessing.Manager().list()
    processidx = multiprocessing.Value('i', 0)
    lock = multiprocessing.Lock()
    def subproc(aFileNames, aTargetBinPath, aFuzzargs, aLock, aTestCasePath):
        (master, slave) = pty.openpty()
        for ifilename in aFileNames:
            crashpath = crashdir + ifilename
            tcurrtrace = minimizer.runpoconce(aTargetBinPath, fuzzargs, crashpath, aTestCasePath, slave)
            with aLock:
                processidx.value += 1
            print_yellow("[+] [%d/%d] checking poc: %s"%(processidx.value, len(crashfiles), ifilename), '\r')
            with aLock:
                allcrashresults.append(tcurrtrace)
    allsubs = []
    eachassignmentcount = len(crashfiles) // pcount
    if eachassignmentcount == 0:
        eachassignmentcount = 1
    if suffix:
        alltempfiles = []
        testcaseprefix = '/tmp/%s'%(genrandomname())
        logwarn("using test case prefix %s"%testcaseprefix)
    for i in range(0, len(crashfiles) + eachassignmentcount, eachassignmentcount):
        arr = crashfiles[i: i + eachassignmentcount]
        if len(arr) == 0:
            continue
        time.sleep(random.random() * 0.05)
        if suffix:
            testcasewritepath = '%s%d%s'%(testcaseprefix, i, suffix)
            alltempfiles.append(testcasewritepath)
        p = multiprocessing.Process(target=subproc, args=(arr, targetbinpath, fuzzargs, lock, testcasewritepath))
        p.start()
        allsubs.append(p)
    for p in allsubs:
        p.join()
    if suffix:
        for ipath in alltempfiles:
            os.unlink(ipath)
    allcrashresults = list(allcrashresults)
    for ires in allcrashresults:
        minimizer.checkunique(ires)
    minimizer.printresult(len(crashfiles))
    report_fd.close()

if __name__ == '__main__':
    main()
