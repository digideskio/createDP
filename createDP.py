#!/usr/bin/python
# -*- coding: utf-8 -*-
####################################################################################################
#
# Copyright (c) 2014, JAMF Software, LLC
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
import random
import string
import subprocess
import plistlib
import httplib
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
userCheck = ""



### DO NOT EDIT BELOW THIS LINE ###
def main():
    Utils.verifyVariable("jss_url", jss_url)
    Utils.verifyVariable("jss_username", jss_username)
    Utils.verifyVariable("jss_password", jss_password)
    Utils.verifyVariable("jds_dns_address", jds_dns_address)
    createAFPUsers()
    createAFPShare()
    linkExistingPackages()
    createPackageMonitor()
    if userCheck == "":
        createDP()

def createAFPUsers():
    global readUserPasswd
    global writeUserPasswd
    global userCheck
    print "Creating AFP Users..."
    
    userCheck = Utils.shell_command("/usr/bin/dscl . read /Users/afpReadUsername 2> /dev/null")
    if userCheck != "":
        print "\tAFP users already exist."
        return

    userIDs = Utils.shell_command("/usr/bin/dscl . list /Users UniqueID | awk '{print $2}'").splitlines()
    userIDs.sort(key=int)
    print "\tLast user ID: " + userIDs[-1]
    readUserID = int(userIDs[-1]) + 1
    if readUserPasswd == "":
        readUserPasswd = Utils.random_string()
    writeUserID = int(userIDs[-1]) + 2
    if writeUserPasswd == "":
        writeUserPasswd = Utils.random_string()

    print "\tCreating AFP Read User with ID: " + str(readUserID) + "..."
    print "\tPassword: " + readUserPasswd
    Utils.shell_command("/usr/bin/dscl . create /Users/afpReadUsername")
    Utils.shell_command("/usr/bin/dscl . create /Users/afpReadUsername UniqueID " + str(readUserID))
    Utils.shell_command("/usr/bin/dscl . create /Users/afpReadUsername PrimaryGroupID 20")
    Utils.shell_command("/usr/bin/dscl . create /Users/afpReadUsername RealName afpReadUsername")
    Utils.shell_command("/usr/bin/dscl . create /Users/afpReadUsername UserShell /bin/bash")
    Utils.shell_command("/usr/bin/dscl . passwd /Users/afpReadUsername " + readUserPasswd)
    
    print "\tCreating AFP Write User with ID: " + str(writeUserID) + "..."
    #print "\tPassword: " + writeUserPasswd
    Utils.shell_command("/usr/bin/dscl . create /Users/afpWriteUsername")
    Utils.shell_command("/usr/bin/dscl . create /Users/afpWriteUsername UniqueID " + str(writeUserID))
    Utils.shell_command("/usr/bin/dscl . create /Users/afpWriteUsername PrimaryGroupID 20")
    Utils.shell_command("/usr/bin/dscl . create /Users/afpWriteUsername RealName afpWriteUsername")
    Utils.shell_command("/usr/bin/dscl . create /Users/afpWriteUsername UserShell /bin/bash")
    Utils.shell_command("/usr/bin/dscl . passwd /Users/afpWriteUsername " + writeUserPasswd)


def createAFPShare():
    print "Creating AFP Share..."
    Utils.shell_command("/bin/mkdir -p /Shared\ Items/CasperShare/Packages")
    Utils.shell_command("/usr/sbin/sharing -a /Shared\ Items/CasperShare")

    print "\tAssigning permissions..."
    Utils.shell_command("/bin/chmod -R +a \"afpReadUsername allow list,search,readattr,readextattr,readsecurity,file_inherit,directory_inherit\" /Shared\ Items/CasperShare")
    Utils.shell_command("/bin/chmod -R +a \"afpWriteUsername allow list,add_file,search,add_subdirectory,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,file_inherit,directory_inherit\" /Shared\ Items/CasperShare")
    Utils.shell_command("/usr/sbin/sharing -s 100")
    Utils.shell_command("/usr/bin/dscl . append /Groups/com.apple.access_afp GroupMembership afpReadUsername")
    Utils.shell_command("/usr/bin/dscl . append /Groups/com.apple.access_afp GroupMembership afpWriteUsername")

    print "\tStarting AFP..."
    Utils.shell_command("/Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin start afp")


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
    Utils.shell_command("/bin/launchctl unload /Library/LaunchDaemons/com.jamfsoftware.jds.packageMonitor.plist")
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
        opener = urllib2.build_opener(urllib2.HTTPHandler)
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


main()