#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# a simple mail merge script that opens an email template mailmerge.txt
# and fills in data from a csv file mailmerge.csv
# The number of emails sent equals the number of records in the csv file
# lists of multiple recipient email addresses are separated by a single space
# the field names in the csv file correspond to variable names in the email template

import sci, os, sys, glob, io, csv, json, argparse, glob, time 
import easygui, getpass, socket, logging, tempfile, inspect  
if sys.platform == "win32":
    import win10toast, winreg

class KeyboardInterruptError(Exception): pass

#constants
__app__ = "Mail Merge"
__ver__ = "1.0"
__ver_date__ = "2020-07-21" 
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
fh = logging.FileHandler(os.path.join(tempfile.gettempdir(),"Mailmerge.debug.txt"))
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.info('username: %s  temp: %s' % (USERNAME, tempfile.gettempdir()))

def main(args):
    """ main entry point """

    start = time.time()
    currdir = os.getcwd()

    # set environment var for valid CA SSL cert
    if not OS.startswith('linux'):
        os.environ["REQUESTS_CA_BUNDLE"] = os.path.join(get_script_dir(), "cacert.pem")

    attachments=glob.glob(os.path.join(currdir,"attachments"))
    print (attachments)

    msg = "First, enter the information common to all email in this batch. Then you will be asked for a 'mailmerge.csv' file that contains information about recipients and a 'mailmerge.txt' file that contains the email body and variables."
    title = "Sending mail merge"
    fieldNames = ["Sender","Subject","BCC"]
    fieldValues = ["Your Name <email@domain.com>", "Enter a descriptive subject", "first_bcc@domain.com second_bcc@domain.com"]  # we start with blanks for the values
    fieldValues = easygui.multenterbox(msg, title, fieldNames, fieldValues)
    
    fromaddr = fieldValues[0]
    subject = fieldValues[1]
    bcc = fieldValues[2].split(" ")

    # # make sure that none of the fields was left blank
    # while 1:
    #     if fieldValues == None: break
    #     errmsg = ""
    #     for i in range(len(fieldNames)):
    #         if fieldValues[i].strip() == "":
    #             errmsg = errmsg + ('"%s" is a required field.\n\n' % fieldNames[i])
    #         if errmsg == "": break # no problems found
    #         fieldValues = easygui.multenterbox(errmsg, title, fieldNames, fieldValues)

    print("Reply was:", fieldValues)

    easygui.msgbox(msg="Please select mailmerge.csv. This file should at least contain columns with header names 'to' and 'cc' and perhaps 'firstname' or 'surname'", title="Select mailmerge.csv")
    mmcsv = easygui.fileopenbox(msg="mailmerge.csv",title="Select mailmerge.csv",default='*mailmerge.csv',multiple=False) #filetypes=["*.csv", ["*.*", "All files"]]
    easygui.msgbox(msg="Please select mailmerge.txt. This file should contain the email body and at least the 'firstname' variable such as 'Dear {firstname},' in curly brackets", title="Select mailmerge.txt")
    mmtxt = easygui.fileopenbox(msg="mailmerge.txt. This file should at least contain a field with the header names 'to' and 'cc'",title="Select mailmerge.csv",default='*mailmerge.txt',multiple=False)

    if not mmcsv or not mmtxt:
        return False

    ########################

    with open(mmtxt, 'r') as f:
        body = f.read()    #.replace('\n', '')

    totalrows = 0
    with open(mmcsv, 'r') as c:
        rows = csv.DictReader(c, dialect='excel')
        for r in rows:
            totalrows += 1

    mypath = getMyFile()
    toaster = win10toast.ToastNotifier()

    with open(mmcsv, 'r') as c:
        rows = csv.DictReader(c, dialect='excel')
        fnames = rows.fieldnames
        print(fnames)

        if easygui.ynbox(msg="Are you sure you want to send %s email(s) as mailmerge now? (y/n)" % totalrows,title="Continue?", choices=("Yes", "No")):

            toaster.show_toast(
                "Sending mailmerge emails ....",
                "massmails using mailmerge.csv and mailmerge.txt.",
                icon_path=mypath,
                duration=5,
                threaded=True)

            for row in rows:
                if 'sendme' in row:
                    if row['sendme'] == '0':
                        print('Skipping %s ..' % lab)
                        continue
                body = fillBody(row,fnames,body)
                if 'to' in row:
                    to=row['to'].strip().split(' ')
                if 'cc' in row:
                    cc=row['cc'].strip().split(' ')
                if 'bcc' in row:
                    bcc=row['bcc'].strip().split(' ')
                print('   sending email "%s" to:%s cc:%s' % (subject ,to, cc))
                ret = sci.tools.mail_send(to, subject, body, fromaddr=fromaddr, cc=cc, bcc=bcc, attachments=attachments)

    #curruser = pwd.getpwuid(os.getuid()).pw_name

    #j = requests.get("https://toolbox.fhcrc.org/json/folderactions.json").json()
	
    end = time.time()
    print("\nTotal Time: %s sec (%s min)" % ("{0:.1f}".format(end-start),"{0:.1f}".format((end-start)/60)))


def fillBody(row,fieldnames,body):
    for f in fieldnames:
        if f in ['from', 'to', 'cc', 'bbc', 'attachments', 'subject']:
            continue
        body = body.replace('{%s}' % f,row[f])
    return body

def get_script_dir(follow_symlinks=True):
    if getattr(sys, 'frozen', False): # py2exe, PyInstaller, cx_Freeze
        path = os.path.abspath(sys.executable)
    else:
        path = inspect.getabsfile(get_script_dir)
    if follow_symlinks:
        path = os.path.realpath(path)
    return os.path.dirname(path)
    
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
        return setup_read_linux()
    elif OS == "win32":
        #logger.info('detected Windows OS')
        return setup_read_win()
    elif OS == "darwin":
        return setup_read_mac()
    else:
        print("Could not detect your platform: '%s'" % OS)
        return setup_read_linux()

    return authlist

def setup_write():

    OS = sys.platform
    if OS == "linux2" or OS == "linux":
        return setup_write_linux()
    elif OS == "win32":
        return setup_write_win()
    elif OS == "darwin":
        return setup_write_mac()
    else:
        print("Could not detect your platform: '%s'" % OS)
        return setup_write_linux()

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

    MyHKEY = HKEY_CURRENT_USER
    try:
        mykey = winreg.OpenKey(MyHKEY,'SOFTWARE\Classes\Directory\shell\ScicompFolderActions', 0, winreg.KEY_ALL_ACCESS)
        return True
    except:
        return False
    
def setup_write_win():
    """ setup is executed if this program is started without any command line args. """
    import winreg as winreg

    myPath = getMyFile()
    MyHKEY = HKEY_CURRENT_USER

    ret = winreg.SetValue(MyHKEY,'SOFTWARE\Classes\Directory\shell\ScicompFolderActions',REG_SZ,'SciComp Folder Actions ...')
    mykey = winreg.OpenKey(MyHKEY,'SOFTWARE\Classes\Directory\shell\ScicompFolderActions', 0, winreg.KEY_ALL_ACCESS)
    winreg.SetValueEx(mykey, "Icon", None, REG_SZ, '"%s",0' % myPath)
    mykey.Close()
    ret = winreg.SetValue(MyHKEY,'SOFTWARE\Classes\Directory\shell\ScicompFolderActions\command',REG_SZ,'"%s" --folder "%%1"' % myPath)

    # ret = winreg.SetValue(MyHKEY,'SOFTWARE\FredHutch\ScicompFolderActions',REG_SZ,'ScicompFolderActions settings')
    # mykey = winreg.OpenKey(MyHKEY,'SOFTWARE\FredHutch\ScicompFolderActions', 0, winreg.KEY_ALL_ACCESS)
    # winreg.SetValueEx(mykey, "xxx", None, REG_SZ, "ccc")
    # winreg.SetValueEx(mykey, "yyy", None, REG_SZ, "hhh")        
    # mykey.Close()
    return True
    

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
    parser = argparse.ArgumentParser(prog='SwiftClientGUI.py',
        description='get email addresses ')
    parser.add_argument( '--folder', '-f', dest='folder',
        action='store',
        help='a folder on a posix file system ',
        default='' )
    parser.add_argument( '--install', '-s', dest='install',
        action='store_true',
        help=' execute the installer',
        default=False )

    args = parser.parse_args()
    return args

if __name__ == '__main__':
    # Parse command-line arguments
    args = parse_arguments()
    sys.exit(main(args))
