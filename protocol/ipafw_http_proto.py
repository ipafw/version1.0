from cmn_Pass_Fail import Pass_Fail,html_fail,html_pass,FAIL,PASS
from robot.libraries.BuiltIn import BuiltIn
import re
import datetime
import os
import sys
import traceback
from robot.api import logger
from lxml import etree
from StringIO import StringIO

PASS = '<b style="color:green">PASS</b>'
FAIL = '<b style="color:red">FAIL</b>'



class HTTPMessageValidation():

    def __init__(self):
        self.xpath = ""
        self.file_name = ""
        self.http_lines = ""
        self.xmlascii = ""
        self.XMLNamespaces = {
                                'SOAP-ENV' : 'http://schemas.xmlsoap.org/soap/envelope/',
                                'mm7' : 'http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-0',
                                'SOAP-ENC' : "http://schemas.xmlsoap.org/soap/encoding/",
                                'xsi' : "http://www.w3.org/2001/XMLSchema-instance",
                                'xsd' : "http://www.w3.org/2001/XMLSchema",
                                'ns1' : "http://www.3gpp.org/ftp/Specs/archive/23_series/23.140/schema/REL-6-MM7-1-0"
                             }
        
    def setHTTPXPath (self, xpath):
        self.xpath = xpath

    def setXMLNamespaces (self, ns_key, ns_value):
        self.XMLNamespaces[ns_key] = ns_value
        
    def getHTTPResponseCode (self, packet):
        return packet.http._all_fields ['http.response.code']

    def getHTTPRequestMethod (self, packet):
        return packet.http._all_fields ['http.request.method']

    def getHTTPRequestURI (self, packet):
        return packet.http._all_fields ['http.request.uri']

    def getHTTPRequestVersion (self, packet):
        return packet.http._all_fields ['http.request.version']

    def getHTTPUserAgent (self, packet):
        return packet.http._all_fields ['http.user_agent']

    def getHTTPContentLength (self, packet):
        return packet.http._all_fields ['http.content_length']

    def getHTTPContentType (self, packet):
        return packet.http._all_fields ['http.content_type']

    def getHTTPResponseFrameIn (self, packet):
        try :
            if hasattr (packet.http, 'response_in') :
                return packet.http.response_in
            else :
                print "http_message_validation: getHTTPResponseFrameIn: no response_in attribute"
                return ""
        except Exception as e:
            print ("\thttp_message_validation: getHTTPResponseFrameIn: Error while parsing http packet: " + repr(e))


    def getHTTPRequestFrameIn (self, packet):
        try :
            if hasattr (packet.http, 'prev_request_in') :
                return packet.http.prev_request_in
            elif hasattr (packet.http, 'request_in') :
                return packet.http.request_in
            else :
                return ""
        except Exception as e:
            print ("\thttp_message_validation: getHTTPRequestFrameIn : Error while parsing http packet: " + repr(e))

        return ""

    def tsharkHTTP (self, pcap_file, frame_number, path='/tmp/'):
        tmp_file = path + "http_" + datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d_%H-%M-%S') + ".txt"
        print "http_message_validation: tsharkHTTP: The tmp file is: ", tmp_file

        try:
            cmd1 = "tshark"
            cmd2 = ("-r %s -Y frame.number==%s -Vx > %s" % (path + "/" + pcap_file, str(frame_number), tmp_file))
            cmd = cmd1 + " " + cmd2
            print "http_message_validation: tsharkHTTP: Tshark Command: ", cmd

            os.system(cmd)
            self.file_name = tmp_file
            return tmp_file
        except Exception as E:
            print "\thttp_message_validation: tsharkHTTP: Exception occurred in HTTP tshark parsing: ", str(E)

        return None

    def readHTTPPacket (self, filename=None):
        if filename == None:
            filename = self.file_name
        try:
            print "http_message_validation: readHTTPPacket: File to read: \n", filename
            with open(filename,'r') as f :
                self.http_lines = f.read()

            self.xmlascii = self.http_lines[self.http_lines.find('<?xml'):self.http_lines.find('0000  ')]
            print "http_message_validation: readHTTPPacket: XML data is:\n", self.xmlascii
        except Exception as E:
            print "\thttp_message_validation: readHTTPPacket: Exception occurred in reading HTTP packet: ", str(E)

    def getHTTPRequestXmlData (self, packet, xPath=None):
        if xPath == None:
            xPath = self.xpath
        try:
            if hasattr (packet, 'mime_multipart') != False :
                if hasattr (packet.mime_multipart, 'mime_multipart.part') != False :
                    mime_multipart = packet.mime_multipart._all_fields['mime_multipart.part'].decode("hex")
                    # Get only the xml section from mime_multipart
                    xmlascii = mime_multipart[mime_multipart.find('<?xml') : mime_multipart.find('</SOAP-ENV:Envelope>')]
                    xmlascii = xmlascii + '</SOAP-ENV:Envelope>'
                    print "http_message_validation: getHTTPRequestXmlData: XML data is:\n", xmlascii
                    return self.getHTTPXmlText(xmlNode=xmlascii, xPath=xPath)
                
                else:
                    print "http_message_validation: getHTTPRequestXmlData: Packet %s does not have mime_multipart field" % str(packet.frame_info.number)
            else:
                print "http_message_validation: getHTTPRequestXmlData: Packet %s does not have MIME layer" % str(packet.frame_info.number)
                
        except Exception as e:
            print ("\thttp_message_validation: getHTTPRequestXmlData : Error while parsing xml: " + repr(e))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_traceback)

        return None

    def getHTTPXmlText (self, xmlNode=None, xPath=None):
        if xmlNode == None:
            xmlNode = self.xmlascii
        if xPath == None:
            xPath = self.xpath
        try:
            xmldoc  = StringIO(xmlNode)
            xtree   = etree.parse(xmldoc)
            xroot   = xtree.xpath(xPath, namespaces=self.XMLNamespaces)
            print "http_message_validation: getHTTPXmlText: XML XPath: ", xPath
            print "http_message_validation: getHTTPXmlText: XML Tag object: ", xroot[0]
            print "http_message_validation: getHTTPXmlText: XML Tag: ", xroot[0].tag
            print "http_message_validation: getHTTPXmlText: XML Text: ", xroot[0].text
            print "http_message_validation: getHTTPXmlText: XML Text Strip: ", xroot[0].text.strip()
            return xroot[0].text.strip()
        except Exception as e:
            print ("\thttp_message_validation: getHTTPXmlText : Error while parsing xml: " + repr(e))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_traceback)

    def getHTTPXmlRequestTransID (self, packet):
        xpath = '/SOAP-ENV:Envelope/SOAP-ENV:Header/mm7:TransactionID'
        return self.getHTTPRequestXmlData (packet, xPath=xpath)
    
    def getHTTPXmlRequestShortCode (self, packet):
        xpath = '/SOAP-ENV:Envelope/SOAP-ENV:Body/mm7:SubmitReq/mm7:SenderIdentification/mm7:SenderAddress/mm7:ShortCode'
        return self.getHTTPRequestXmlData (packet, xPath=xpath)

    def getHTTPXmlRequestMSISDN (self, packet):
        xpath = '/SOAP-ENV:Envelope/SOAP-ENV:Body/mm7:SubmitReq/mm7:Recipients/mm7:To/mm7:Number'
        return self.getHTTPRequestXmlData (packet, xPath=xpath)

    def getHTTPXmlRequestSubject (self, packet):
        xpath = '/SOAP-ENV:Envelope/SOAP-ENV:Body/mm7:SubmitReq/mm7:Subject'
        return self.getHTTPRequestXmlData (packet, xPath=xpath)

    def getHTTPXmlRequestContent (self, packet):
        xpath = '/SOAP-ENV:Envelope/SOAP-ENV:Body/mm7:SubmitReq/mm7:Content'
        return self.getHTTPRequestXmlData (packet, xPath=xpath)

    def getHTTPXmlResponseTransID (self, packet):
        xpath = '/SOAP-ENV:Envelope/SOAP-ENV:Header/ns1:TransactionID'
        return self.getHTTPXmlText (xPath=xpath)

    def getHTTPXmlResponseStatusCode(self, packet):
        xpath = '/SOAP-ENV:Envelope/SOAP-ENV:Body/ns1:SubmitRsp/ns1:Status/ns1:StatusCode'
        return self.getHTTPXmlText (xPath=xpath)

    def getHTTPXmlResponseMessageID (self, packet):
        xpath = '/SOAP-ENV:Envelope/SOAP-ENV:Body/ns1:SubmitRsp/ns1:MessageID'
        return self.getHTTPXmlText (xPath=xpath)

    def validateHTTPMessage(self, packet, validate_args, prt = []):
	status = True
        for key in validate_args:
            value = validate_args[key]
            all_http_fields = packet.http._all_fields

            if key == 'REQUEST_METHOD':
                actual_value = self.getHTTPRequestMethod (packet)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'REQUEST_URI':
                actual_value = self.getHTTPRequestURI (packet)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'X-WAP-PROFILE':
                actual_value = self.getXWapProfile (packet)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'CONTENT_TYPE':
                actual_value = self.getHTTPContentType (packet)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'MSISDN':
                actual_value = self.getMSISDN (packet.http)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value in value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'MSISDN_ANY':
                actual_value = self.getMSISDN (packet.http)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value in value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'CHARGINGID':
                actual_value = self.getChargingID (packet.http)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False
          
            if key == 'SGSNIP':
                actual_value = self.getSGSNIP (packet.http)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'IMSI':
                actual_value = self.getIMSI (packet.http)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'RESPONSE_CODE':
                actual_value = self.getHTTPResponseCode (packet)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'XML_MSISDN':
                actual_value = self.getHTTPXmlRequestMSISDN (packet)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'XML_SHORTCODE':
                actual_value = self.getHTTPXmlRequestShortCode (packet)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value == actual_value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'XML_STATUSCODE':
                actual_value = self.getHTTPXmlResponseStatusCode (packet)
                print "http_message_validation: validateHTTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value == actual_value :
                    print "http_message_validation: validateHTTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

        return status

    def updateResults(self, result, message):
        message2 = ''
        if result == True:
            message1 = '<b style="color:green">%s</b> ' % message
            message2 = message1 + " - " + html_pass
        elif result == False:
            message1 = '<b style="color:red">%s</b> ' % message
            message2 = message1 + " - " + html_fail
        elif result == 'MsgBody':
            for i in message:
                message2 = message2 + i + '\n'
                #if 'Expected' in i:
                    #message2 = message2+i+'  -  '+html_fail+'\n'
                #else:
                    #message2 = message2+i+'  -  '+html_pass+'\n'
        return message2


    def getMSISDN (self, http_packet) :
        try:
            var = re.search (r'MSISDN: (.*?)\\r\\n', str(http_packet))
            print "http_message_validation: getMSISDN: val: ", var.group(1)
            return var.group(1).replace('+', '')
        except Exception as e:
            print ("\thttp_message_validation: getMSISDN: Error while parsing http packet: " + repr(e))
            return ""

    def getChargingID (self, http_packet) :
        try:
            var = re.search (r'CHARGINGID: (.*?)\\r\\n', str(http_packet))
            print "http_message_validation: getChargingID: val: ", var.group(1)
            return var.group(1)
        except Exception as e:
            print ("\thttp_message_validation: getChargingID: Error while parsing http packet: " + repr(e))
            return ""

    def getSGSNIP (self, http_packet) :
        try:
            var = re.search (r'SGSNIP: (.*?)\\r\\n', str(http_packet))
            print "http_message_validation: getSGSNIP: val: ", var.group(1)
            return var.group(1)
        except Exception as e:
            print ("\thttp_message_validation: getSGSNIP: Error while parsing http packet: " + repr(e))
            return ""


    def getIMSI (self, http_packet) :
        try:
            var = re.search (r'IMSI: (.*?)\\r\\n', str(http_packet))
            print "http_message_validation: getIMSI: val: ", var.group(1)
            return var.group(1)
        except Exception as e:
            print ("\thttp_message_validation: getIMSI: Error while parsing http packet: " + repr(e))
            return ""

    def getXWapProfile (self, http_packet) :
        try:
            var = re.search (r'x-wap-profile: (.*?)\\r\\n', str(http_packet))
            print "http_message_validation: getXWapProfile: val: ", var.group(1)
            return var.group(1)
        except Exception as e:
            print ("\thttp_message_validation: getXWapProfile: Error while parsing http packet: " + repr(e))
            return ""

