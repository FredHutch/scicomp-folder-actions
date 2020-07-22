#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
File Owner Mailer is a simple tool that gathers email addresses for all users 
who have written files in a certain directory tree and opens the default mailer 
with a mailto:link that contains all email addresses.
"""

import sys, os, inspect, argparse, logging, json
import getpass, tempfile, socket, base64, time, random
import easygui, webbrowser, requests, paramiko
import win32api, win32con, win32security
if sys.platform == "win32":
    import win10toast

#import packaging, packaging.version, packaging.markers # needed since Python 3.5
#import packaging.requirements, packaging.specifiers, packaging.utils

class KeyboardInterruptError(Exception): pass

#constants
__app__ = "srun tester"
__ver__ = "0.1"
__ver_date__ = "2020-07-10" 
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
fh = logging.FileHandler(os.path.join(tempfile.gettempdir(),"sruntest.debug.txt"))
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.info('username: %s  temp: %s' % (USERNAME, tempfile.gettempdir()))

#sys.stdout = open(os.path.join(tempfile.gettempdir(),"sruntest.out.txt"), 'w')
#sys.stderr = open(os.path.join(tempfile.gettempdir(),"sruntest.err.txt"), 'w')

def main(args):
    """ main entry point """

    # set environment var for valid CA SSL cert
    if not OS.startswith('linux'):
        os.environ["REQUESTS_CA_BUNDLE"] = os.path.join(get_script_dir(), "cacert.pem")

    mypath = getMyFile()
    if OS == "win32":
        toaster = win10toast.ToastNotifier()
        toaster.show_toast(
            "SciComp SSH Tester",
            "Testing ssh...",
            icon_path=mypath,
            duration=3,
            threaded=True) 
   
    test = ssh_exec_gss([args.host], ['srun hostname'])
    for t,std in test.items():
        easygui.codebox(' Output of command "%s":' % t,'Show Slurm Output',"\n".join(std[0].readlines()))
        #for line in std[0].readlines():
        #    print(line.strip())

def ssh_exec_gss(hosts, commands):
    """ execute list of commands via ssh """
    if not isinstance(hosts, list):
        print('hosts parameter in ssh_exec needs to be a list of (randomly picked) hosts')
        return {}
    if not isinstance(commands, list):
        print('commands parameter in ssh_exec needs to be a list')
        return {}
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(
        paramiko.AutoAddPolicy())
    random.shuffle(hosts)
    ssh.auth_method = "gssapi-with-mic"
    ssh.connect(hosts[0],  gss_auth=True)
    ret = {}
    for command in commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        ret[command]=[stdout, stderr]
    return ret


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

def setup_read():    
    if OS == "linux2" or OS == "linux":
        authlist = setup_read_linux()
    elif OS == "win32":
        logger.info('detected Windows OS')
        authlist = setup_read_win()
    elif OS == "darwin":
        authlist = setup_read_mac()
    else:
        print("Could not detect your platform: '%s'" % OS)
        authlist = setup_read_linux()

    return authlist

def setup_write():

    OS = sys.platform
    if OS == "linux2" or OS == "linux":
        return setup_write_linux(fieldValues)
    elif OS == "win32":
        return setup_write_win(fieldValues)
    elif OS == "darwin":
        return setup_write_mac(fieldValues)
    else:
        print("Could not detect your platform: '%s'" % OS)
        return setup_write_linux(fieldValues)

def setup_read_linux():
    if sys.hexversion > 0x03000000:
        from configparser import ConfigParser 
    else:
        from ConfigParser import ConfigParser

    authlist = [""]*4

    homedir = os.path.expanduser('~')
    if not os.path.exists(homedir+'/.swift'):
        return authlist
        
    # instantiate
    config = ConfigParser()

    try:
        # parse existing file
        config.read(homedir+'/.swift/swiftclient.ini')

        # add a new section and some values
        authlist[0] = config.get('default', 'auth_url')
        authlist[1] = config.get('default', 'tenant')
        authlist[2] = config.get('default', 'user')
        authlist[3] = decode(KEY,config.get('default', 'pass'))
    except:
        print('error reading config swiftclient.ini')
    
    return authlist

def setup_read_win():
    if sys.hexversion > 0x03000000:
        import winreg as winreg
    else:
        import _winreg as winreg

    authlist = [""]*4

    MyHKEY = HKEY_CURRENT_USER
    try:
        mykey = winreg.OpenKey(MyHKEY,'SOFTWARE\OpenStack\SwiftClient', 0, winreg.KEY_ALL_ACCESS)
        authlist[0] = winreg.QueryValueEx(mykey,"auth_url")[0]
        logger.info('auth_url: %s' % authlist[0])
        authlist[1] = winreg.QueryValueEx(mykey,"tenant")[0]
        logger.info('tenant: %s' % authlist[1])
        authlist[2] = winreg.QueryValueEx(mykey,"user")[0]
        logger.info('user: %s' % authlist[2])        
        authlist[3] = decode(KEY,winreg.QueryValueEx(mykey,"pass")[0])
    except:
        pass

    return authlist
    
    
def setup_write_win(authlist):
    """ setup is executed if this program is started without any command line args. """
    import winreg as winreg

    myPath = getMyFile()
    MyHKEY = HKEY_CURRENT_USER

    ret = winreg.SetValue(MyHKEY,'SOFTWARE\Classes\Directory\shell\FileownerMailer',REG_SZ,'Send eMail to Users')
    mykey = winreg.OpenKey(MyHKEY,'SOFTWARE\Classes\Directory\shell\FileownerMailer', 0, winreg.KEY_ALL_ACCESS)
    winreg.SetValueEx(mykey, "Icon", None, REG_SZ, '"%s",0' % myPath)
    mykey.Close()
    ret = winreg.SetValue(MyHKEY,'SOFTWARE\Classes\Directory\shell\FileownerMailer\command',REG_SZ,'"%s" --folder "%%1"' % myPath)

    ret = winreg.SetValue(MyHKEY,'SOFTWARE\FredHutch\FileownerMailer',REG_SZ,'File owner mailer settings')
    mykey = winreg.OpenKey(MyHKEY,'SOFTWARE\FredHutch\FileownerMailer', 0, winreg.KEY_ALL_ACCESS)
    winreg.SetValueEx(mykey, "xxx", None, REG_SZ, "ccc")
    winreg.SetValueEx(mykey, "yyy", None, REG_SZ, "hhh")        
    mykey.Close()
    

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

                
def getstat(path):
    """ returns the stat information of a file"""
    statinfo=None
    try:
        statinfo=os.lstat(path)
    except (IOError, OSError) as e:   # FileNotFoundError only since python 3.3
        if args.debug:
            sys.stderr.write(str(e))            
    except:
        raise
    return statinfo

def setfiletime(path,attr="atime"):
    """ sets the a time of a file to the current time """
    try:
        statinfo=getstat(path)
        if attr=="atime" or attr=="all":
            os.utime(path,(time.time(),statinfo.st_atime))
        if attr=="mtime" or attr=="all":
            os.utime(path,(time.time(),statinfo.st_mtime))        
        return True
    except Exception as err:
        sys.stderr.write(str(err))
        sys.stderr.write('\n')
        return False

def uid2user(uidNumber):
    """ attempts to convert uidNumber to username """
    import pwd
    try:
        return pwd.getpwuid(int(uidNumber)).pw_name
    except Exception as err:
        sys.stderr.write(str(err))
        sys.stderr.write('\n')
        return str(uidNumber)

def fileowner_win(filename):
    sd = win32security.GetFileSecurity (filename, win32security.OWNER_SECURITY_INFORMATION)
    owner_sid = sd.GetSecurityDescriptorOwner ()
    name, domain, type = win32security.LookupAccountSid (None, owner_sid)
    return name

def list2file(mylist,path):
    """ dumps a list into a text file, one line per item"""
    try:
        with open(path,'w') as f:
            for item in mylist:
                f.write("{}\r\n".format(item))
        return True
    except Exception as err:
        sys.stderr.write(str(err))
        sys.stderr.write('\n')
        return False

def pathlist2file(mylist,path,root):
    """ dumps a list into a text file, one line per item, but removes
         a root folder from all paths. Used for --files-from feature in rsync"""
    try:
        with open(path,'w') as f:
            for item in mylist:
                f.write("{}\r\n".format(item[len(root):]))
        return True
    except Exception as err:
        sys.stderr.write(str(err))
        sys.stderr.write('\n')
        return False

def mywalk(top, noparallel=False, skipdirs=['.snapshot',]):
    """ returns subset of os.walk  """

    for root, dirs, files in os.walk(top,topdown=True,onerror=walkerr):
        for skipdir in skipdirs:
            if skipdir in dirs:
                dirs.remove(skipdir)  # don't visit this directory 
        yield root, dirs, files

def walkerr(oserr):    
    sys.stderr.write(str(oserr))
    sys.stderr.write('\n')
    return 0

def getemail(json, username):
    email=jsearchone(json,"uid",username,"mail")
    if email:
        return email
    else:
        return username+'@fredffhutch.org'

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
    parser = argparse.ArgumentParser(prog='sruntest',
        description='get email addresses ')
    parser.add_argument( '--host', '-s', dest='host',
        action='store',
        help='a hostname to connect to',
        default='' )
                            
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    # Parse command-line arguments
    args = parse_arguments()
    sys.exit(main(args))
