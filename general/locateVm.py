#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#    Library for RHEV-M VM Management
#
#    Copyright (C) 2013 Christian Bolz <cbolz at redhat dot com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    Modifications:
#       2013-11-10 - Daniel Augustin <daniel at noris dot de>
#


version="0.1.2"
lastchange="2013-11-20"
homepage="http://github.com/RedHatEMEA/RHEV-Tools"
author="Christian Bolz <cbolz at redhat dot com>"


"""
locateVm.py - Locate a VM by name and return the IP of the host it is running on
"""

import urllib2
import sys
import base64
from xml.etree import ElementTree
import subprocess 
import getopt
import traceback
 
#Example
#ADDR     = "10.35.24.4"
#API_PORT = "8443"
#USER     = "admin@internal"  # Must provide @domain
#PASSWD   = "P@ssw0rd"
#VM       = "RHEL6x64"



def usage():
	print """
	locateVm.py - Locate a VM by name and return the IP of the host it is running on
	Usage:  locateVm.py | [arg].internal..[argN]
	Options:
	--help:                Print this help screen.
	--address=<FQDN or IP: Use non-default (127.0.0.1) IP to access the RHEV-M API.
	--port=<PORT>:         Use non-default (8443) port to access the RHEV-M API.
	--user=<Username>:     Use non-default (admin@internal) username to access RHEV-M API. Must use USER@DOMAIN 
	--password=<PASSWORD>: Enter the API user password
	--vm=<VM NAME>:        Enter name of the requested VM
	
	If no options are entered, or --password and/or --vm options are missing, will enter interactive mode.
	"""
 

def getArgs():
	global ADDR, API_PORT, VM, USER, PASSWD
	print "Missing some options. Entering interactive mode..."
	i = raw_input('Enter the RHEV-Manager address [' + ADDR + ']: ' )
	if i != '':
		ADDR = i
	i = raw_input('Enter the RHEV-Manager API port [' + API_PORT + ']: ' )
	if i != '':
		API_PORT = i
	i = raw_input('Enter the RHEV-Manager API user name [' + USER + ']: ' )
	if i != '':
		USER = i
	i = raw_input('Enter the RHEV-Manager API password [' + PASSWD + ']: ' )
	if i != '':
		PASSWD = i
	i = raw_input('Enter the Virtual Machine name [' + VM + ']: ' )
	if i != '':
		VM = i
		
def run(): 
    global ADDR, API_PORT, VM, USER, PASSWD
    # Setting URL
    URL      = "https://" + ADDR + ":" + API_PORT + "/api/vms?search=" + VM
    request = urllib2.Request(URL)
    #print "Connecting to: " + URL

    base64string = base64.encodestring('%s:%s' % (USER, PASSWD)).strip()
    request.add_header("Authorization", "Basic %s" % base64string)

    try:
        xmldata = urllib2.urlopen(request).read()
    except urllib2.URLError, e:
        print "Error: cannot connect to REST API: %s" % (e)
        print "Try to login using the same user/pass by the Admin Portal and check the error!"
        sys.exit(2)

    tree = ElementTree.XML(xmldata)
    lst = tree.findall("vm")

    host = "None"

    for item in lst:
        host = item.find("host").attrib["id"]
        if host == "None":
            print "VM is not running on any of the hosts"
            sys.exit(0)
    URL = "https://" + ADDR + ":" + API_PORT + "/api/hosts/" + host
    request = urllib2.Request(URL)
    #print "Connecting to " + URL
    base64string = base64.encodestring('%s:%s' % (USER, PASSWD)).strip()
    request.add_header("Authorization", "Basic %s" % base64string)

    try:
        xmldata = urllib2.urlopen(request).read()
    except urllib2.URLError, e:
        print "Error: cannot connect to REST API: %s" % (e)
        print "Try to login using the same user/pass by the Admin Portal and check the error!"
        sys.exit(2)
	 
    tree = ElementTree.XML(xmldata)
    list = tree.findall("host")
	 
    ip = tree.findtext("address")
	 
    return ip


def startConsole(host,vm):
    # Adjust for RHEV 3.1
    #cmd = "ssh -t -i /etc/pki/rhevm/keys/rhevm_id_rsa root@" + host + " 'virsh -c qemu+tls://$(grep \"Subject:\" /etc/pki/vdsm/certs/vdsmcert.pem | cut -d= -f3)/system console " + vm + "'" 
    cmd = "ssh -t -i /etc/pki/ovirt-engine/keys/engine_id_rsa root@" + host + " 'virsh -c qemu+tls://$(openssl x509 -in /etc/pki/vdsm/certs/vdsmcert.pem -noout -text | grep Subject | grep CN | cut -d"=" -f3)/system console " + vm + "'" 
    subprocess.call(cmd, shell=True)


if __name__ == '__main__':
    #Setting defaults, to be overriden by user 
    API_PORT  = "8443"
    USER      = "admin@internal"
    ADDR      = "127.0.0.1"
    PASSWD    = ""
    VM        = ""
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ['help','address=','port=','user=','password=','vm='])
        for o,v in opts:
            #print (o,v)
            if o == "-h" or o == "--help":
                usage()
                sys.exit(0)
            elif o == '--address':
			    ADDR = v
            elif o == '--port':
			    API_PORT = v
            elif o == '--user':
                USER = v
            elif o == '--password':
                PASSWD = v
            elif o == '--vm':
                VM = v
            else:
                print "Wrong argument " + v
                sys.exit(1)	
		

		if len(opts) <= 1:
			usage()
			exit(1)
        print "%s %s %s %s %s len - %s" % (ADDR , API_PORT , USER , PASSWD , VM, len(opts))
    except SystemExit as e:
        raise e
    except:
        print traceback.format_exc()
        exit(1)
    
    if PASSWD == "" or VM == "":
        getArgs()

        
        
    host = run()
    
    print "WARNING: Entering VM console, press ^] to exit..."
    startConsole(host,VM)
    
    sys.exit(0)



