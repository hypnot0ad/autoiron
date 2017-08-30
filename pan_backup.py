#!/usr/bin/python
# -*- coding: utf-8 -*-

''' Takes input (from stdin), parses it into the proper format, and then
    sends a POST request to a firewall in order to add the user id and IP
    address into the firewall's logs. '''

##########################################################################
### TODO LIST:
### - Sanitize inputs for apps
### - create a log for failed rules
### - Trim names to be less than 31 characters
### - Desensitise case
### - DONE = Automatically get API key as function
### - DONE = Take URL and Credentials as user input
### - Order the Security Policy
##########################################################################
    
from xml.etree import ElementTree
from xml.dom import minidom
import urllib
import sys, getopt
import re
import csv
import ssl

#########################################################################
### Take input variables for use later ###
#########################################################################
argv = sys.argv[1:]
outputfile = ''
try:
    opts, args = getopt.getopt(argv,"hd:u:p:f:",["api-host=","user=","csv-file="])
except getopt.GetoptError:
    print 'upload-secpolicy.py -d <api IP or FQDN> -u <API User Name> -p <API Password> -f <CSV filename>'
    sys.exit(2)
for opt, arg in opts:
    if opt == "-h":
        print 'upload-secpolicy.py -d <API IP or FQDN> -u <API User Name> -p <API Password> -f <CSV Filename>'
        sys.exit()
    elif opt in ("-d", "--api-host"):
        api_host = arg
    elif opt in ("-u", "--api-user"):
        api_user = arg
    elif opt in ("-p", "--api-password"):
        api_password = arg
    elif opt in ("-f", "--csv-file"):
        csv_file = arg

#########################################################################

###################
###  CONSTANTS  ###
###################
VERSION = 1.1
FIREWALL_URL    = 'https://' + api_host + '/api/'
XML_FILENAME    = 'xmloutput.xml'
KEY = ""
config_action = ""
config_args    = { 'type': 'config', 'action': 'show', 'key': KEY}
keygen_args = { 'type': 'keygen', 'user': api_user, 'password': api_password}
##########


def keyRequest(api_user,api_password,api_host,keygen_args):
    global KEY
    encoded_args = urllib.urlencode(keygen_args)
    url = FIREWALL_URL + '?' + encoded_args
    #"?type=keygen&user=" + api_user + "&password=" + api_password

    print 'SENDING REQUEST:\n', url
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    response = urllib.urlopen(url, context=ctx).read()

    #Error check
    if "response status = 'success'" not in response: 
        print 'error message'
        KEY = ""
    else:
        KEY = ElementTree.fromstring(response)[0][0].text
        print 'Your KEY:\n', KEY

    return KEY

def sendRequest(config_args):
#def sendRequest(query_args, xml):
    """ Sends a request to the firewall, including the provided query_args 
    in dict format. Returns the response from the firewall (for future proofing.)"""

    encoded_args = urllib.urlencode(config_args)
#    encoded_args = str(query_args)
#    url = FIREWALL_URL + '?' + encoded_args + '&element=' + xml
    url = FIREWALL_URL + '?' + encoded_args
    print '######################################'
    print 'SENDING REQUEST:', url
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    response = urllib.urlopen(url, context=ctx).read()


### Filter out the responses from known good uploads ###
    if 'code="12"' in response:
        print '######################################'
        print 'ERROR CODE 12:'
        #rint '\n\nRESPONSE:\n\n', response

        print "Syntax bad yours is!"
        xmlresponse = ElementTree.fromstring(response)
        for i in xmlresponse[0][0]:
            count = 0
            if i.tag == "line":
                count = count + 1
                print i.text
        #print ElementTree.fromstring(response)[0][0][0].text

    elif 'code="13"' in response: 
        print '\n\nRESPONSE:\n\n', response
        print ElementTree.fromstring(response)[0][0].text
        
    elif 'code="20"' in response: 
        print '\n\nRESPONSE:\n\n', response
        print 'IT WORKED! (Fluke...)'
        print ElementTree.fromstring(response)[0][0].text

    #Fix this, its probably not specific enough...
    elif 'success' in response: 
        print '\n\nRESPONSE:\n\n', response
        print 'Something was a success (not you!) maybe a config?'
        print ElementTree.fromstring(response)[0][0].attrib
        #write link to new function to write the config to file
        f = open( api_host + '-config.txt', 'w' )
        f.write( response )
        f.close()

    else:
        print "You buggered it so bad I dont know what you did!"
        print ElementTree.fromstring(response)[0][0].text
        print response

    return response


###################################################################
#   MAIN                                                          #
###################################################################

def main():
    global api_user
    global api_password
    #if key is empty:
    if not KEY:
        print 'You dont got the key! Requesting now...'
        key_request = keyRequest(api_user, api_password, api_host, keygen_args)
    else:
        print 'You should never see this!'

    print KEY
    print "with great key, comes great keying"        
    #with open("//home//nick//Desktop//scripting//pan_config//test.csv") as csvfile:
    with open(csv_file) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=';')
        #next(readCSV, None) # skip the header
        lines_read = 0
            
        for row in readCSV:
            print 'Received line', lines_read

            ### DO THIS BETTER ###
            FIREWALL_URL=row[0]
            api_user=row[1]
            api_password=row[2]

            #row_list = [host, user, password]

            # Generate xpath
            #xpath = generateXPath(name, position, devicegroup)

            # Generate XML and save it to 'xml'
            #xml = generateXML2(name, description, tag, fromzone, srcip, user, hip, tozone, dstip, app, service, action, profile, log_end, position, devicegroup)
            #xml = generateXML2(row_list)
                
            # Write xml as XML into XML_FILENAME
            #writeXMLToFile(xml, XML_FILENAME)

            #lines_read = lines_read + 1
            
        # Send request
            #config_args['element'] = xml
            #config_args['xpath'] = xpath
            config_args['key'] = KEY
            #print query_args
            response = sendRequest(config_args)

#        response = sendRequest(query_args, xml)

        # Be a good boy and close the csv file
        csvfile.close()

if __name__ == '__main__':
#    main(sys.argv[1:])

    main()
