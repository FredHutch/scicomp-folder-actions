#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File Owner Mailer is a simple tool that gathers email addresses for all users 
who have written files in a certain directory tree and opens the default mailer 
with a mailto:link that contains all email addresses.
"""

import sys, os, inspect, argparse, logging, json
import getpass, tempfile, socket, base64, time
import webbrowser, requests
import win32api, win32con, win32security, win32timezone
if sys.platform == "win32":
    import win10toast

#import packaging, packaging.version, packaging.markers # needed since Python 3.5
#import packaging.requirements, packaging.specifiers, packaging.utils

class KeyboardInterruptError(Exception): pass

#constants
__app__ = "File Owner Mailer"
__ver__ = "0.1"
__ver_date__ = "2020-07-01" 
__copy_date__ = "2020"
__author__ = "dirkpetersen"
__company__ = "Fred Hutch, Seattle"

HKEY_CURRENT_USER = -2147483647
HKEY_LOCAL_MACHINE = -2147483646
REG_SZ = 1
REG_DWORD = 4
KEY = 'gjkdjgndfhdgfgdldfgj902u54nkk34u8os'
USERNAME = getpass.getuser()
OS = sys.platform
IP = socket.gethostbyname(socket.gethostname())
    

logger = logging.getLogger('FOM')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler(os.path.join(tempfile.gettempdir(),"FileOwnerMailer.debug.txt"))
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.info('username: %s  temp: %s' % (USERNAME, tempfile.gettempdir()))

#sys.stdout = open(os.path.join(tempfile.gettempdir(),"SwiftClientGUI.out.txt"), 'w')
#sys.stderr = open(os.path.join(tempfile.gettempdir(),"SwiftClientGUI.err.txt"), 'w')

def main(args):
    """ main entry point """

    #sys.exit()

    # set environment var for valid CA SSL cert
    if not OS.startswith('linux'):
        os.environ["REQUESTS_CA_BUNDLE"] = os.path.join(get_script_dir(), "cacert.pem")

    if not args.folder:
        print('please use the --folder <foldername> option.')
        return False

    mypath = getMyFile()
    toaster = win10toast.ToastNotifier()
    toaster.show_toast(
        "SciComp File Owner Mailer",
        "Finding Owners for files in %s....." % args.folder,
        icon_path=mypath,
        duration=5,
        threaded=True)    

    args.folder=args.folder.rstrip('/')
    args.folder=args.folder.replace('\\','/')
    basename=os.path.basename(args.folder)

    start = time.time()
    interval = 1
    maxinterval = 10

    lastcheck = 0
    lastt = 0
    
    currdir = os.getcwd()
    #curruser = pwd.getpwuid(os.getuid()).pw_name

    fileowners = {}
    excludeusers = ["Administrator", "Administrators", "SYSTEM", "root"]

    if args.folder == '/':
        print('root folder not allowed !')
        return False

    numfiles=0
    numfolders=0 

    try:
        j = requests.get('https://toolbox.fhcrc.org/json/user.json').json()
    except:
        j = None
        print ('Could not access json file https://toolbox.fhcrc.org/json/user.json')

    for root, folders, files in mywalk(args.folder):
        #print(root)
        #for folder in folders:
            #print ('...folder:%s' % folder)
        # check if the user wanted to archive
        numfolders+=1
        numfiles+=len(files)
        check = time.time()
        if lastcheck+interval<check:
            t=numfolders+numfiles
            print ("folders: %s, files: %s, avg objects/s: %s, last objects/s: %s, current path: %s" 
                    % (numfolders, numfiles, "{0:.0f}".format(t/(check-start)), "{0:.0f}".format((t-lastt)/(check-lastcheck)), root))
            lastcheck=check
            lastt=t
            interval+=1
            if maxinterval<=interval:
                interval=maxinterval

        for f in files:
            p=os.path.join(root,f)
            try:
                user=fileowner_win(p)
            except:
                continue
            if user not in excludeusers:
                email = getemail(j, user)
                fileowners.setdefault(user, email) 

    print(fileowners)
    emails=""
    for k,v in fileowners.items():
        emails = emails+v+"; "

    end = time.time()
    print("\nTotal Time: %s sec (%s min)" % ("{0:.1f}".format(end-start),"{0:.1f}".format((end-start)/60)))

    webbrowser.open("mailto:{}?subject=To file owners in folder '{}'".format(emails,args.folder), new=1)

def get_script_dir(follow_symlinks=True):
    if getattr(sys, 'frozen', False): # py2exe, PyInstaller, cx_Freeze
        path = os.path.abspath(sys.executable)
    else:
        path = inspect.getabsfile(get_script_dir)
    if follow_symlinks:
        path = os.path.realpath(path)
    return os.path.dirname(path)

def getMyFile():
    try:
        if hasattr(sys,"frozen"):
            myFile = os.path.abspath(sys.executable)
        else:
            myFile = os.path.abspath( __file__ )
    except:
        #if hasattr(sys,"frozen") and sys.frozen == "windows_exe": ... does not work
        myFile = os.path.abspath( __file__ )
    return myFile

def encode(KEY, clear):
    enc = []
    b64=None
    for i in range(len(clear)):
        key_c = KEY[i % len(KEY)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
        b64 = base64.urlsafe_b64encode("".join(enc).encode('utf-8'))
    if b64:
        return b64.decode('utf-8')
    return ""

def decode(KEY, enc):
    dec = []
    b64 = base64.urlsafe_b64decode(enc.encode('utf-8'))
    enc = b64.decode('utf-8')
    for i in range(len(enc)):
        key_c = KEY[i % len(KEY)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

    

def startswithpath(pathlist, pathstr):
    """ checks if at least one of the paths in a list of paths starts with a string """
    for path in pathlist:
        if (os.path.join(pathstr, '')).startswith(path):
            return True
    return False

def getstartpath(pathlist, pathstr):
    """ return the path from pathlist  that is the frist part of pathstr"""
    for path in pathlist:
        if (os.path.join(pathstr, '')).startswith(path):
            return path
    return ''

                
def fileowner_win(filename):
    sd = win32security.GetFileSecurity (filename, win32security.OWNER_SECURITY_INFORMATION)
    owner_sid = sd.GetSecurityDescriptorOwner ()
    name, domain, type = win32security.LookupAccountSid (None, owner_sid)
    return name


def mywalk(top, skipdirs=['.snapshot','.snap']):
    """ returns subset of os.walk  """

    for root, dirs, files in os.walk(top,topdown=True,onerror=walkerr):
        for skipdir in skipdirs:
            if skipdir in dirs:
                dirs.remove(skipdir)  # don't visit this directory 
        yield root, dirs, files

def walkerr(oserr):
    #easygui.msgbox("Entered walkerr!", "Entered walkerr")
    try:
        print(str(oserr))
    except:
        print('Exception in walkerr.')
    return 0

def getemail(json, username):
    if not json:
        return username+'@fredhutch.org'
    email=jsearchone(json,"uid",username,"mail")
    if email:
        return email
    else:
        return username+'@fredhutch.org'

def jsearchone(json,sfld,search,rfld):
    """ return the first search result of a column based search """
    for j in json:
        if j[sfld]==search:
            if j[sfld]:
                return j[rfld]
            else:
                return j[rfld].strip()


def parse_arguments():
    """
    Gather command-line arguments.
    """
    parser = argparse.ArgumentParser(prog='SwiftClientGUI.py',
        description='get email addresses ')
    parser.add_argument( '--folder', '-f', dest='folder',
        action='store',
        help='a folder on a posix file system ',
        default='' )
                            
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    # Parse command-line arguments
    args = parse_arguments()
    sys.exit(main(args))
