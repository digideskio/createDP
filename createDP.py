#!/usr/bin/python
# -*- coding: utf-8 -*-
####################################################################################################
#
# Copyright (c) 2015, JAMF Software, LLC
# All rights reserved.
#
#
# OWNERSHIP OF INTELLECTUAL PROPERTY:
#
#    JAMF Software, LLC (JAMF) will retain ownership of all proprietary rights to the source code and
#    object code of the Software. Upon full payment of the fees set forth in this agreement, JAMF
#    will grant to Customer a non-exclusive, non-transferable license to install and use the Software
#    within its own organization.
#
#    The license shall authorize Customer to:
#        a)    Install the Software on computer systems owned, leased, or otherwise controlled by
#        Customer
#        b)    Utilize the Software for its internal data processing purposes
#        c)    Copy the Software only as necessary to exercise the rights granted in this Agreement
#
#
# WARRANTY AND DISCLAIMER:
#
#    JAMF will offer the following express warranties through the Agreement:
#
#    Warranty of Software Performance
#    JAMF warrants that for a period of 5 (five) business days following acceptance (receipt) of
#    the Software by Customer, the Software will be free from defects in workmanship and materials,
#    and will conform as closely as possible to the specifications provided in the Development Plan
#    contained within this Agreement. If material reproducible programming errors are discovered
#    during the warranty period, JAMF shall promptly remedy them at no additional expense to Customer.
#    This warranty to Customer shall be null and void if Customer is in default under this Agreement
#    or if the nonconformance is due to:
#
#        a)    Hardware failures due to defects, power problems, environmental problems, or any cause
#        other than the Software itself
#        b) ModificationoralterationoftheSoftware,OperatingSystems,orHardwaretargetsspecified in the
#        Development Plan contained within this Agreement
#        c)    Misuse, errors, or negligence by Customer, its employees, or agents in operating the
#        Software
#
#    JAMF shall not be obligated to cure any defect unless Customer notifies JAMF of the existence
#    and nature of such defect promptly upon discovery within the warranty period.
#
#    Warranty of Title:
#    JAMF owns and reserves the right to license or convey title to the Software and documentation
#    that arises out of the nature of this Agreement.
#
#    Warranty Against Disablement
#    JAMF expressly warrants that no portion of the Software contains or will contain any protection
#    feature designed to prevent its use. This includes, without limitation, any computer virus, worm,
#    software lock, drop dead device, Trojan-horse routine, trap door, time bomb or any other codes
#    or instructions that may be used to access, delete, damage, or disable Customer Software or
#    computer system. JAMF further warrants that it will not impair the operation of the Software in
#    any other way than by order of a court of law.
#
#    Warranty of Compatibility
#    JAMF warrants that the Software shall be compatible with Customer specific hardware and software
#    titles and versions as set forth in the Development Plan of this Agreement. No warranty, express,
#    or implied will be made on versions of hardware or software not mentioned in the Development Plan
#    of this agreement.
#
#    The warranties set forth in this Agreement are the only warranties granted by JAMF. JAMF disclaims
#    all other warranties, express or implied, including, but not limited to, any implied warranties
#    of merchantability or fitness for a particular purpose.
#
#
#
# LIMITATION OF LIABILITY:
#
#    In no event shall JAMF be liable to Customer for lost profits of Customer, or special or
#    consequential damages, even if JAMF has been advised of the possibility of such damages.
#
#    JAMF Software's total liability under this Agreement for damages, costs and expenses, regardless of cause
#    shall not exceed the total amount of fees paid to JAMF by Customer under this Agreement.
#
#    JAMF shall not be liable for any claim or demand made against Customer by any third party.
#
#    Customer shall indemnify JAMF against all claims, liabilities and costs, including reasonable
#    attorney fees, of defending any third party claim or suit arising out of the use of the Software
#    provided under this Agreement.
#
####################################################################################################

import sys
import os.path
import random
import string
import subprocess
import plistlib
import httplib
import socket
import ssl
import urllib2
import base64
import xml.etree.cElementTree as ET


### Fill these in ###
jss_url = ""
jss_username = ""
jss_password = ""
jds_dns_address = "" #<-This must be reachable by clients

### If left blank, these will be randomized...
readUserPasswd = ""
writeUserPasswd = ""



### DO NOT EDIT BELOW THIS LINE ###
userCheck = ""
def main():
    Utils.verifyVariable("jss_url", jss_url)
    Utils.verifyVariable("jss_username", jss_username)
    Utils.verifyVariable("jss_password", jss_password)
    Utils.verifyVariable("jds_dns_address", jds_dns_address)
    createAFPShare(getUID("afpReadUsername"), getUID("afpWriteUsername"))
    linkExistingPackages()
    createPackageMonitor()
    if userCheck == "":
    	createDP()
    else:
	print "WARNING: \"afpReadUsername\" and \"afpWriteUsername\" Users already exist.  Please delete these users and run the script again to ensure that the DP is created properly in the JSS, or manually create the distribution point in your JSS with the proper custom credentials."

def getUID(username):
    global readUserPasswd
    global writeUserPasswd  
    global userCheck  
    userCheck = Utils.shell_command("/usr/bin/dscl . read /Users/" + username + " 2> /dev/null")
    if userCheck == "":
        print "Creating user: " + username + "..."
        userIDs = Utils.shell_command("/usr/bin/dscl . list /Users UniqueID | awk '{print $2}'").splitlines()
        userIDs.sort(key=int)
        print "\tLast user ID: " + userIDs[-1]
        userID = int(userIDs[-1]) + 1
        userPasswd = Utils.random_string()
        if username == "afpReadUsername":
            if readUserPasswd == "":
                #Assign random password
                readUserPasswd = userPasswd
            else:
                #Use provided password
                userPasswd = readUserPasswd
        else:
            if writeUserPasswd == "":
                #Assign random password
                writeUserPasswd = userPasswd
            else:
            	#Use provided password
            	userPasswd = writeUserPasswd

        print "\tCreating user " + username + " with ID: " + str(userID) + "..."
        Utils.shell_command("/usr/bin/dscl . create /Users/" + username)
        Utils.shell_command("/usr/bin/dscl . create /Users/" + username + " UniqueID " + str(userID))
        Utils.shell_command("/usr/bin/dscl . create /Users/" + username + " PrimaryGroupID 20")
        Utils.shell_command("/usr/bin/dscl . create /Users/" + username + " RealName " + username)
        Utils.shell_command("/usr/bin/dscl . create /Users/" + username + " UserShell /bin/bash")
        Utils.shell_command("/usr/bin/dscl . passwd /Users/" + username + " " + userPasswd)
        
    return Utils.shell_command("/usr/bin/dscl . read /Users/" + username + " GeneratedUID | awk '{print $2}'")


def createAFPShare(readUserGeneratedUID, writeUserGeneratedUID):
    print "Creating AFP Share..."
    Utils.shell_command("/bin/mkdir -p /Shared\ Items/CasperShare/Packages")
    Utils.shell_command("/usr/sbin/sharing -a /Shared\ Items/CasperShare")

    print "\tAssigning permissions..."
    Utils.shell_command("/bin/chmod -R +a \"afpReadUsername allow list,search,readattr,readextattr,readsecurity,file_inherit,directory_inherit\" /Shared\ Items/CasperShare")
    Utils.shell_command("/bin/chmod -R +a \"afpWriteUsername allow list,add_file,search,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit\" /Shared\ Items/CasperShare")
    Utils.shell_command("/usr/sbin/sharing -s 100")
    Utils.shell_command("/usr/bin/dscl . append /Groups/com.apple.access_afp GroupMembership afpReadUsername 2> /dev/null")
    Utils.shell_command("/usr/bin/dscl . append /Groups/com.apple.access_afp GroupMembership afpWriteUsername 2> /dev/null")
    
    print "\tDetermining Sharepoint Structure..."
    sharepointGroups = Utils.shell_command("/usr/bin/dscl . list /Groups | grep sharepoint 2> /dev/null").splitlines()
    for group in sharepointGroups:
        shareName = Utils.shell_command("/usr/bin/dscl . read /Groups/" + group + " RealName | awk '{print $2}'")
        if shareName == "CasperShare":
            print "\t\tGroup for CasperShare Membership: " + group
            Utils.shell_command("/usr/bin/dscl . append /Groups/" + group + " GroupMembership afpReadUsername 2> /dev/null")
            Utils.shell_command("/usr/bin/dscl . append /Groups/" + group + " GroupMembers " + readUserGeneratedUID + "")
            Utils.shell_command("/usr/bin/dscl . append /Groups/" + group + " GroupMembership afpWriteUsername 2> /dev/null")
            Utils.shell_command("/usr/bin/dscl . append /Groups/" + group + " GroupMembers " + writeUserGeneratedUID + "")
            break

    if os.path.exists("/Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin"):
        print "\tStarting AFP..."
        Utils.shell_command("/Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin start afp 2> /dev/null")
    else:
        print "\tServer Admin not installed.  Please start AFP manually."


def linkExistingPackages():
    print "Creating links for existing packages..."
    Utils.shell_command("/bin/ln /Library/JDS/shares/CasperShare/* /Shared\ Items/CasperShare/Packages/ 2> /dev/null")


def createPackageMonitor():
    print "Creating Package Monitor..."
    
    print "\tCreating LaunchDaemon..."
    pl = dict(
              Label = "com.jamfsoftware.jds.packageMonitor",
              ProgramArguments = ["/bin/sh", "-c", "/bin/ln \"`/usr/bin/find /Library/JDS/shares/CasperShare/ -type f -size +0c -mtime -7 -print0 | /usr/bin/xargs -0 ls -1t | /usr/bin/head -1`\" /Shared\ Items/CasperShare/Packages/"],
              WatchPaths = ["/Library/JDS/shares/CasperShare"]
              )
    plistlib.writePlist(pl, "/Library/LaunchDaemons/com.jamfsoftware.jds.packageMonitor.plist")
    
    print "\tLoading LaunchDaemon..."
    Utils.shell_command("/bin/launchctl unload /Library/LaunchDaemons/com.jamfsoftware.jds.packageMonitor.plist 2> /dev/null")
    Utils.shell_command("/bin/launchctl load /Library/LaunchDaemons/com.jamfsoftware.jds.packageMonitor.plist")


def createDP():
    print "Creating Distribution Point..."
    try:
        if jss_url.endswith('/'):
            url = jss_url + "JSSResource/distributionpoints/id/0"
        else:
            url = jss_url + "/JSSResource/distributionpoints/id/0"
        #Write out the XML string with new data to be submitted
        xmlDataString = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>
        <distribution_point>
            <name>''' + jds_dns_address + '''</name>
            <ip_address>''' + jds_dns_address + '''</ip_address>
            <is_master>false</is_master>
            <connection_type>AFP</connection_type>
            <share_name>CasperShare</share_name>
            <share_port>548</share_port>
            <read_only_username>afpReadUsername</read_only_username>
            <read_only_password>''' + readUserPasswd + '''</read_only_password>
            <read_write_username>afpWriteUsername</read_write_username>
            <read_write_password>''' + writeUserPasswd + '''</read_write_password>
        </distribution_point>'''
        #print "\tData Sent: " + xmlDataString
        opener = urllib2.build_opener(TLS1Handler())
        request = urllib2.Request(url,xmlDataString)
        request.add_header("Authorization", Utils.getAuthHeader(jss_username,jss_password))
        request.add_header('Content-Type', 'application/xml')
        request.get_method = lambda: 'POST'
        opener.open(request)
    except httplib.HTTPException as inst:
        print "\tException: %s" % inst
    except ValueError as inst:
        print "\tException submitting XML: %s" % inst
    except urllib2.HTTPError as inst:
        print "\tException submitting XML: %s" % inst
    except:
        print "\tUnexpected error submitting XML:", sys.exc_info()


class Utils:
    
    @staticmethod
    def verifyVariable(name, value):
        if value == "":
            print "Error: Please specify a value for variable \"" + name + "\""
            sys.exit(1)
    
    @staticmethod
    def random_string(size=30):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for x in range(size))
    
    @staticmethod
    def shell_command(*args):
        """Run a shell command exaxtly as it appears and return stdout"""
        process = subprocess.Popen(stdout=subprocess.PIPE, shell=True, *args)
        return process.communicate()[0].strip()
    
    @staticmethod
    def noshell_command(*args):
        """Runs a command without using the shell. Used where 'user' is part of the command"""
        process = subprocess.Popen(stdout=subprocess.PIPE, shell=False, *args)
        return process.communicate()[0].strip()
    
    @staticmethod
    def getAuthHeader(u,p):
        # Compute base64 representation of the authentication token.
        token = base64.b64encode('%s:%s' % (u,p))
        return "Basic %s" % token
        
#Force TLS since the JSS now requires TLS+ due to the POODLE vulnerability
class TLS1Connection(httplib.HTTPSConnection):
    def __init__(self, host, **kwargs):
        httplib.HTTPSConnection.__init__(self, host, **kwargs)
 
    def connect(self):
        sock = socket.create_connection((self.host, self.port),
                self.timeout, self.source_address)
        if getattr(self, '_tunnel_host', None):
            self.sock = sock
            self._tunnel()
 
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                ssl_version=ssl.PROTOCOL_TLSv1)
 
class TLS1Handler(urllib2.HTTPSHandler):
    def __init__(self):
        urllib2.HTTPSHandler.__init__(self)
 
    def https_open(self, req):
        return self.do_open(TLS1Connection, req)


main()