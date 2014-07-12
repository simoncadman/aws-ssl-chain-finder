#! /usr/bin/env python3

from optparse import OptionParser
import os
import subprocess
import logging
import re
import sys
import glob

def verifyCert(certfile, certchain=None):
    depth = 0
    args = ['openssl','verify','-purpose','sslserver']
    if certchain != None:
        args.append('-CAfile')
        args.append(certchain)
    args.append(certfile)
    logging.debug(args)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    output = p.communicate()[0]
    logging.debug(output)
    returnval = p.wait()
    if returnval != 0:
        m = re.search('at (\d?) depth lookup', output.decode("utf-8"))
        depth = m.group(1)
        logging.debug("Depth is %s" % depth)
    return returnval == 0, int(depth)

parser = OptionParser(usage="usage: %prog [options] certificate chaindir")
parser.add_option("-l", "--loglevel", dest="loglevel", help="Loglevel - debug")
(options, args) = parser.parse_args()
if len(args) < 2:
    parser.error("wrong number of arguments")

certificate = args[0]
certchaindir = args[1]
logging.basicConfig()
logger = logging.getLogger()
if options.loglevel != None:
    if options.loglevel == 'debug':
        logger.setLevel(logging.DEBUG)

# verify without chain
if verifyCert(certificate)[0]:
    print("Certificate seems to be valid without chain")
else:
    #print("Certificate invalid without chain, finding chain")
    filelist = glob.glob(os.path.join(certchaindir,'*.crt'))
    logging.debug('Files found:')
    logging.debug(filelist)
    if len(filelist) < 1:
        sys.stderr.write("No chain files found\n")
        sys.exit(1)
    # find for expected depth
    tempfile = '/tmp/temp-certchain.crt'
    validchain = ""
    chain = ""
    previousdepth = 0
    success = False
    tryid = 0
    trycount = 0
    
    while not success:
        if trycount > len(filelist):
            os.unlink(tempfile)
            sys.stderr.write("Complete chain not found\n")
            sys.exit(1)
        
        if tryid >= len(filelist):
            tryid = 0
        
        logging.debug("Trying %s", filelist[tryid])
        certfile = open(filelist[tryid], 'rb')
        certfiledata = certfile.read()
        chain = chain + certfiledata.decode("utf-8")
        
        tempcertfile = open(tempfile, 'w')
        tempcertfile.write(chain)
        tempcertfile.close()
        
        success, depth = verifyCert(certificate,tempfile)
        if depth > previousdepth:
            validchain = chain
            tryid = 0
            previousdepth = depth
        elif not success:
            chain = validchain
            tryid += 1
            trycount += 1
        
        if success:
            validchain = chain
            print(validchain)
            os.unlink(tempfile)
            sys.exit(0)
    