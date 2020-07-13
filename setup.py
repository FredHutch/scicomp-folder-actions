# -*- coding: utf-8 -*-

# A simple setup script to create an executable that includes
# the python-swiftclient and easygui. 

import sys, os, setuptools
import requests.certs
from cx_Freeze import setup, Executable

pydir = os.path.dirname(sys.executable)
dlldir = os.path.join(pydir,'DLLs')

os.environ['TCL_LIBRARY'] = pydir + "\\tcl\\tcl8.6"
os.environ['TK_LIBRARY'] = pydir + "\\tcl\\tk8.6"

base = None
basegui = None
if sys.platform == 'win32':
    basegui = 'Win32GUI'

options = {
    'build_exe': {
        'packages': [],
        'includes': [],
        'excludes': [],
        'include_files':[
            (requests.certs.where(),'cacert.pem'),
            'README.md',
            dlldir+'\\tk86t.dll',
            dlldir+'\\tcl86t.dll',
            #('resources', 'resources'),
            #('config.ini', 'config.ini')
            ],
   # not in cx 5.0     'compressed': True,
        #'path': sys.path + ['modules'],
        'include_msvcr': True,
		# 'compressed': True,
   # not in cx 5.0     'icon': 'swift.ico'
    },
    'bdist_msi': {
        'upgrade_code': '{{66620F3A-DC3A-11E2-B341-ZADRE23i4DCD}',
        'add_to_path': True,
		'all_users': True,
		#'install_script': 'folderactions.py', 
		'install_icon': 'fredhutch.ico',
        'initial_target_dir': 'C:\\Program Files\\Fred Hutch\\SciComp',
    }
}

##bdist_msi_options = {
##    'upgrade_code': '{66620F3A-DC3A-11E2-B341-002219E9B01E}',
##    'add_to_path': False,
##    'initial_target_dir': r'[ProgramFilesFolder]\%s\%s' % (company_name, product_name),
##    }
##
##build_exe_options = {
##    'includes': ['atexit', 'PySide.QtNetwork'],
##    }

##setup(name=product_name,
##      version='1.0.0',
##      description='blah',
##      executables=[exe],
##      options={
##          'bdist_msi': bdist_msi_options,
##          'build_exe': build_exe_options})
##

executables = [
    Executable(
               script='folderactions.py',
               shortcutName='SciComp Folder Actions Install',
               shortcutDir='ProgramMenuFolder',
               #compress=True,
               icon='fredhutch.ico',
               #targetDir='OpenStack\\Swift',
               base=basegui),
    Executable('fileownermailer.py',
               icon='mail-256.ico',
               base=basegui),
    Executable('sruntest.py',
               icon='fredhutch.ico',
               base=basegui)
]

setup(name='Fred Hutch SciComp Folder Actions',
      version='1.0',
      description='run actions by right clicking on a folder',
      options=options,
      executables=executables,
	  #scripts = ['folderactions.py',],
      )
