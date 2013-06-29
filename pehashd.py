#!/usr/bin/env python

import hashlib
from multiprocessing import Process
import socket
import os
import ConfigParser
import sys
import json
import time
import datetime
import copy
import binascii
import bz2
from bitstring import BitStream, BitArray
import math
import pefile
import magic
import ssdeep

def log(msg):
    print "[%s] PID=%d %s"%(datetime.datetime.now(), os.getpid(), msg)
    sys.stdout.flush()

def roundUp(num):
    winPageBoundary = 4096.
    return int(math.ceil(num/winPageBoundary) * winPageBoundary)

def peHash(pe_data):
    pe = pefile.PE(data=pe_data)
    characteristics = BitArray(uint=pe.FILE_HEADER.Characteristics, length=16)
    subsystem = BitArray(uint=pe.OPTIONAL_HEADER.Subsystem, length=16)

    # Rounded up to page boundary size
    sizeOfStackCommit = BitArray(uint=roundUp(pe.OPTIONAL_HEADER.SizeOfStackCommit), length=32)
    sizeOfHeapCommit = BitArray(uint=roundUp(pe.OPTIONAL_HEADER.SizeOfHeapCommit), length=32)

    #sort these:
    sections = [];
    for section in pe.sections:
        #calculate kolmogrov:
        data = pe.get_memory_mapped_image()[section.VirtualAddress: section.VirtualAddress + section.SizeOfRawData]
        compressedLength = len(bz2.compress(data))

        kolmogrov = 0
        if (section.SizeOfRawData > 0):
            kolmogrov = int(math.ceil((compressedLength/section.SizeOfRawData) * 7.))

        sections.append((section.Name, BitArray(uint=section.VirtualAddress, length=32),BitArray(uint=section.SizeOfRawData, length=32),BitArray(uint=section.Characteristics, length=32),BitArray(uint=kolmogrov, length=16)))
    hash = characteristics[0:8] ^ characteristics[8:16]
    characteristics_hash = characteristics[0:8] ^ characteristics[8:16]
    hash.append(subsystem[0:8] ^ subsystem[8:16])
    subsystem_hash = subsystem[0:8] ^ subsystem[8:16]
    hash.append(sizeOfStackCommit[8:16] ^ sizeOfStackCommit[16:24] ^ sizeOfStackCommit[24:32])
    stackcommit_hash = sizeOfStackCommit[8:16] ^ sizeOfStackCommit[16:24] ^ sizeOfStackCommit[24:32]
    hash.append(sizeOfHeapCommit[8:16] ^ sizeOfHeapCommit[16:24] ^ sizeOfHeapCommit[24:32])
    heapcommit_hash = sizeOfHeapCommit[8:16] ^ sizeOfHeapCommit[16:24] ^ sizeOfHeapCommit[24:32]

    sections_holder = []
    for section in sections:
        section_copy = copy.deepcopy(section)
        section_hash = section_copy[1]
        section_hash.append(section_copy[2])
        section_hash.append(section_copy[3][16:24] ^ section_copy[3][24:32])
        section_hash.append(section_copy[4])
        hash.append(section[1])
        hash.append(section[2])
        hash.append(section[3][16:24] ^ section[3][24:32])
        hash.append(section[4])

        sections_holder.append(str(section_hash))

    return hashlib.md5(str(hash)).hexdigest()

def process_file(filepath, res):
    with open(filepath, 'rb') as pe_file:
        pe_data = pe_file.read()
        res['md5'] =   hashlib.md5(pe_data).hexdigest()
        res['sha1'] =  hashlib.sha1(pe_data).hexdigest()
        res['sha256'] = hashlib.sha256(pe_data).hexdigest()
        res['sha512'] = hashlib.sha512(pe_data).hexdigest()
        res['ssdeep'] = ssdeep.hash(pe_data)

        try:
            res['filetype'] = magic.from_buffer(pe_data)
        except:
            if 'errors' not in res:
                res['errors'] = []
            res['errors'].append('could not determine filetype (%s)'%str(e))

        try:
            res['pe_hash'] = peHash(pe_data)
        except Exception, e:
            if 'errors' not in res:
                res['errors'] = []
            res['errors'].append('could not compute pehash (%s)'%str(e))

def dispatch_client_inet_socket(connfile, max_size):
    while True:
        try:
            filepath = connfile.readline()
            if not filepath: break
  
            start = time.time()
            matches = []
            res = {}
            filepath = filepath.rstrip("\n\r")
            if os.path.exists(filepath):
                if os.path.isfile(filepath):
                    res['file_size'] = os.stat(filepath).st_size
                    process_file(filepath, res)
                else:
                    res['errors'] = ['not a file']
            else:
                res['errors'] = ['file not found']
            end = time.time()
            res['exec_time'] = "%.2fms"%((end-start)*1000)
            connfile.write(json.dumps(res)+"\n")
            connfile.flush()
        except:
            break
    connfile.close()

def write_pidfile(pidfile):
    with open(pidfile, "w") as pid_file:
        pid_file.write("%s\n" % (str(os.getpid())))

def mainloop(host, port, max_size):
    log("Listening on %s:%d ..."%(host, port))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    while True:
        conn, addr = server.accept()
        log("Accepted connection from %s:%d ..."%(addr[0], addr[1]))
        p = Process(target=dispatch_client_inet_socket, args=(conn.makefile(), max_size))
        p.daemon = 1
        p.start()
    server.close()

if  __name__ =='__main__':
    log("Starting ...")
    config = ConfigParser.ConfigParser()
    config.read("pehashd.cfg")

    pidfile     = config.get("server", "pidfile")
    host        = config.get("server", "host")
    port        = config.getint("server", "port")
    max_size    = config.getfloat("server", "max_size_mb")*(2**20)

    sys.stdout.flush()

    if config.getint("server", "daemon") == 1:
        log("Forking ...")
        import daemon
        with daemon.DaemonContext():
            write_pidfile(pidfile)
            mainloop(host, port, max_size)
    else:
        write_pidfile(pidfile)
        mainloop(host, port, max_size)

