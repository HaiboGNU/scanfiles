# -*- coding: UTF-8 -*- 
import multiprocessing
import time
import signal
import argparse
import threading
import os
import queue
import sys
import datetime
import hashlib
import json
import logging
import psutil
import re
from daemon import daemonize
from urllib.request import urlopen
import socket  
from configparser import ConfigParser
import traceback


PY3 = False
if sys.version_info < (2, 7) or sys.version_info > (4,):
    print("WARNING: You're running an untested version of python")
elif sys.version_info > (3,):
    PY3 = True

logger = logging.getLogger("ScanDaemon")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler = logging.FileHandler("/var/log/scanfiles.log")
handler.setFormatter(formatter)
logger.addHandler(handler)


lock = threading.RLock()
#wlock = threading.RLock()
queuelist = []
thread_count = 0
allfiles = 0
outputdir = ''
app = ''
s=""

CONF="scan.conf"
SHARE_Q = queue.Queue()
MAXFILELIST = 100000
TIMEOUT = 10
MAXTHREAD = 300


def send_error(s,app,batchid,exctype,value):
    errordata=dict(app=app, batchid=batchid, errortype="%s"%str(exctype)[8:-2], content="%s"%value)
    res = json.dumps(errordata)
    res +='\n'
    msg=bytes(res, encoding = "utf8")
    s.send(msg)

class MyThread(threading.Thread) :

    def __init__(self, func) :
        super(MyThread, self).__init__()
        self.func = func

    def run(self) :
        self.func()

def scan_gen_file():
    global SHARE_Q
    global thread_count
    global outputdir
    global app
    global allfiles
    global s
    global batchid
    filesize = 0
    empty = False

    #while not SHARE_Q.empty():
    while True:
        try:
            filelist = []
            #try:
            scanpath = SHARE_Q.get(True,TIMEOUT)
            #except:
            #    print("Get form SHARE_Q timeout")
            #    continue
            
            try:
                filelist = os.listdir(scanpath)
            except:
                exctype, value = sys.exc_info() [: 2]
                send_error(s,app,batchid,exctype,value)
                errormsg = str(exctype)[8:-2]
                dirs = dict(dirname=scanpath, files=[], msg=errormsg)
                now = datetime.datetime.now().strftime('%Y%m%d%H')
                lock.acquire()
                with open(outputdir+app+'_'+now+'.data', 'a') as fw:
                   try:
                       fw.write(json.dumps(dirs)+'\n')
                   except:
                       exctype, value = sys.exc_info() [: 2]
                       send_error(s,app,batchid,exctype,value)
                       logger.exception('write file error message')
                lock.release()

                logger.exception("os.listdir timeout: %s"%scanpath)
                continue

            if len(filelist) >= MAXFILELIST:
                logger.exception("The filelist number is very large, ignore it:%s"%scanpath)
                continue
            else:
                flist = []
                fsize = 0
                filesize = len(filelist)
                if filesize == 0:
                    dirs = dict(dirname=scanpath, files=flist)
                    now = datetime.datetime.now().strftime('%Y%m%d%H')
                    lock.acquire()
                    with open(outputdir+app+'_'+now+'.data', 'a') as fw:
                        try:
                            fw.write(json.dumps(dirs)+'\n')
                            #print(dirs)
                            #pass
                        except:
                            exctype, value = sys.exc_info() [: 2]
                            send_error(s,app,batchid,exctype,value)
                            logger.exception('write file error message')
                    lock.release()
                else:
                    for fl in filelist:
                        filename = os.path.join(scanpath,fl)
                        if os.path.exists(filename):
                            # First judge the file type whether is link, then dirctory, and last other types,includes general file, block file, socket file  
                            if os.path.islink(filename):
                                lock.acquire()
                                allfiles += 1
                                fsize += 1
                                lock.release()
                                try:
                                    fileinfo = os.stat(filename)
                                except:
                                    exctype, value = sys.exc_info() [: 2]
                                    send_error(s,app,batchid,exctype,value)
                                    print("link file stat error")
                                    continue
                                srcpath=os.path.abspath(os.readlink(filename))
                                l = dict(tp='link', sz=fileinfo.st_size, mt=int(fileinfo.st_mtime),at=int(fileinfo.st_atime),ct=int(fileinfo.st_ctime),
                                     st=int(time.time()),uid=fileinfo.st_uid,gid=fileinfo.st_gid,fn=fl,src=srcpath)
                                flist.append(l)
                                dirs = dict(dirname=scanpath, files=l)
                                newdata = json.dumps(dirs,ensure_ascii=False)
                                newdata += "\n"
                                now = datetime.datetime.now().strftime('%Y%m%d%H')
                                lock.acquire()
                                with open(outputdir+app+'_'+now+'.data', 'a') as fw:
                                    try:
                                        fw.write(newdata)
                                        #print(dirs)
                                        #pass
                                    except:
                                        exctype, value = sys.exc_info() [: 2]
                                        send_error(s,app,batchid,exctype,value)
                                        logger.exception('write file error message')
                                lock.release()

                            elif os.path.isdir(filename):
                                try:
                                    SHARE_Q.put(filename)
                                except:
                                    exctype, value = sys.exc_info() [: 2]
                                    send_error(s,app,batchid,exctype,value)
                                    print("queue full")
                            #elif os.path.isfile(filename):
                            else:
                                lock.acquire()
                                allfiles += 1
                                fsize += 1
                                #print(allfiles)
                                lock.release()
                                #fileinfo = os.stat(filename)
                                try:
                                    fileinfo = os.stat(filename)
                                except:
                                    print("general file stat error")
                                    continue
                                f = dict(tp='file', sz=fileinfo.st_size, mt=int(fileinfo.st_mtime),at=int(fileinfo.st_atime),ct=int(fileinfo.st_ctime),
                                     st=int(time.time()),uid=fileinfo.st_uid,gid=fileinfo.st_gid,fn=fl)
                                flist.append(f)
                                dirs = dict(dirname=scanpath, files=f)
                                newdata = json.dumps(dirs,ensure_ascii=False)
                                newdata += "\n"
                                now = datetime.datetime.now().strftime('%Y%m%d%H')
                                lock.acquire()
                                with open(outputdir+app+'_'+now+'.data', 'a') as fw:
                                    try:
                                        fw.write(newdata)
                                        #print(dirs)
                                        #pass
                                    except:
                                        exctype, value = sys.exc_info() [: 2]
                                        send_error(s,app,batchid,exctype,value)
                                        logger.exception('write file error message')
                                lock.release()

                            """
                            if fsize%2000 == 0 or fsize == filesize:
                                newdata = ""
                                for fl in flist:
                                    dirs = dict(dirname=scanpath, files=fl)
                                    newdata += json.dumps(dirs,ensure_ascii=False)
                                    newdata += "\n"
                                now = datetime.datetime.now().strftime('%Y%m%d%H')
                                lock.acquire()
                                with open(outputdir+app+'_'+now+'.data', 'a') as fw:
                                    try:
                                        fw.write(newdata)
                                        #print(dirs)
                                        #pass
                                    except:
                                        logger.exception('write file error message')
                                lock.release()
                                flist = []
                            """
            lock.acquire()
            with open("%sthreadnum.txt"%outputdir,"wt") as f:
                print("%s"%(threading.activeCount()-1),file=f)
            lock.release()
        except queue.Empty as e:
            empty = True
            break
        except queue.Full as e:
            exctype, value = sys.exc_info() [: 2]
            send_error(s,app,batchid,exctype,value)
            print("queue full")
        except OSError as e:
            exctype, value = sys.exc_info() [: 2]
            send_error(s,app,batchid,exctype,value)
            print('OSError:', e)
            logger.exception('OSError')
            continue
        except Exception as e:
            exctype, value = sys.exc_info() [: 2]
            send_error(s,app,batchid,exctype,value)
            print('Exception:', e)
            logger.exception('Exception')
            continue
        finally:
            if not empty:
                SHARE_Q.task_done()
            
def gettask(msg):
    tasks = []
    fileinfo = []
    try:
        jsondata = json.loads(msg)
    except:
        exctype, value = sys.exc_info() [: 2]
        send_error(s,app,batchid,exctype,value)
        logger.info("%s is not valid json"%msg)
        return False
    appname = jsondata['appname']
    threadnum = jsondata['threadnum']
    batchid = jsondata['batchid']
    #scandir = [ x for x in jsondata['scandirs'].split(";") ]
    #blackdir = [x for x in jsondata['blackdir'].split(";") ]
    scandir = [ x for x in re.split(r';;',jsondata['scandirs']) ]
    blackdir = [x for x in re.split(r';;',jsondata['blackdir']) ]

    return threadnum,batchid,scandir,blackdir

def getoutdir(app,batchid):
    return '/var/log/scanlog/'+str(app)+'/'+batchid+'/'

def getoutputpath(app,batchid):
    now = datetime.datetime.now().strftime('%Y%m%d%H')
    return '/var/log/'+str(app)+'/'+batchid+'/'+str(app)+now+'.data'

def getscandir(a):
    a=list(set(a))
    a.sort()
    l = len(a)
    i,j = 0,1
   
    while i < l:
        while j < l:
            if a[i] in a[j]:
                a.remove(a[j])
                l -= 1
            j +=1
        i+=1
        j=i+1
    return a

def bad_filename(filename):
    return repr(filename)[1:-1]

def main(app,msg):
    global batchid
    global outputdir
    global thread_count
    global SHARE_Q
    global s

    start = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cfg = ConfigParser()
    try:
        cfg.read(CONF)
    except:
        print("The config file is not found")
        sys.exit()

    port = cfg.getint('server','port')
    serverip = cfg.get('server','ip')
    address = (serverip,port)  
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    try:
        s.connect(address) 
    except:
        print("cannot connect to server")
        logger.error("Client cannot connect to server %s:%s"%(serverip,port))


    threads = []
    thread_count,batchid,scanpath,blackdir = gettask(msg)
    scandir = getscandir(scanpath)
    logger.info("Scaning Start, the info is:\n appname:%s\n batchid:%s\n scandir:%s\n blackdir:%s"%(app,batchid,scandir,blackdir))


    outputdir = getoutdir(app,batchid)
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)

    
    if int(thread_count) < len(scandir):
        thread_count = len(scandir)
    if int(thread_count) > MAXTHREAD:
        thread_count = MAXTHREAD
    #print("thread_count is %s"%thread_count)

    for dirs in scandir:
        SHARE_Q.put(dirs)
    for i in range(int(thread_count)):
        t = MyThread(scan_gen_file)
        #t.setDaemon(True)
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()

    signal.signal(signal.SIGINT, quit)  
    signal.signal(signal.SIGTERM, quit)
    s.close() 
    with open("%sthreadnum.txt"%outputdir,"wt") as f:
        print("%s"%(threading.activeCount()-1),file=f)

    print('start at: '+start)
    print('end at: '+datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print("allfiles: %s" % allfiles)

    logger.info('start at: '+start)
    logger.info('end at: '+datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    logger.info("allfiles: %s" % allfiles)

if __name__ == '__main__':
    '''
    path = sys.argv[1]
    t = time.time()
    app = sys.argv[2]
    msg = sys.argv[3]
    main(app,msg)

    print(allfiles)
    t2 = time.time()
    print(t2-t)
    '''
    if len(sys.argv) < 3:
        print('Usage: {} [start|stop|suspend|wake] [appname]'.format(sys.argv[0]), file=sys.stderr)
        raise SystemExit(1)

    app = sys.argv[2]
    PIDFILE = "/tmp/scan"+app+".pid"

    if sys.argv[1] == 'start':
        logger.info("Receive start command for app: %s"%app)
        if len(sys.argv) != 4:
            print('Usage: {} [start] [appname] [msg]'.format(sys.argv[0]), file=sys.stderr)
            raise SystemExit(1)
        try:
            daemonize(PIDFILE,
                      stdout='/tmp/scanfiles.log',
                      stderr='/tmp/scanfiles.log')
        except RuntimeError as e:
            print(e, file=sys.stderr)
            raise SystemExit(1)
        main(app,sys.argv[3])

    elif sys.argv[1] == 'stop':
        logger.info("Receive stop command for app: %s"%app)
        if os.path.exists(PIDFILE):
            #with open("%sthreadnum.txt"%outputdir,"wt") as f:
            #    print(0,file=f)
            with open(PIDFILE) as f:
                os.kill(int(f.read()), signal.SIGTERM)
        else:
            print('Not running', file=sys.stderr)
            raise SystemExit(1)

    elif sys.argv[1] == 'suspend':
        logger.info("Receive suspend command for app: %s"%app)
        isrun  = False
        if os.path.exists(PIDFILE):
            with open("%sthreadnum.txt"%outputdir,"wt") as f:
                print(0,file=f)
            with open(PIDFILE) as f:
                p = psutil.Process(int(f.read()))
                p.suspend()
        else:
            print('Not running', file=sys.stderr)
            raise SystemExit(1)

    elif sys.argv[1] == 'wake':
        logger.info("Receive wake command for app: %s"%app)
        isrun = True
        if os.path.exists(PIDFILE):
            with open(PIDFILE) as f:
                p = psutil.Process(int(f.read()))
                p.resume()
        else:
            print('Not running', file=sys.stderr)
            raise SystemExit(1)

    else:
        print('Unknown command {!r}'.format(sys.argv[1]), file=sys.stderr)
        raise SystemExit(1)
