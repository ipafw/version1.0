import re
import os
import sys
import datetime
from robot.libraries.BuiltIn   import BuiltIn
from robot.api                 import logger
from collections               import OrderedDict
from cmn_Pass_Fail             import Pass_Fail,html_fail,html_pass,FAIL,PASS

PASS = '<b style="color:green">PASS</b>'
FAIL = '<b style="color:red">FAIL</b>'

class IMFMessageValidation () :

    def tsharkIMFSMTP (self, path, pcap_file, display_filter) :
        tmp_file = path + "/" + datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d_%H-%M-%S') + ".txt"
        print "tsharkIMF: The tmp file is: ", tmp_file

        try:
            cmd1 = "tshark"
            cmd2 = ("-2 -r %s -Y \'%s\' -d 'tcp.port==1525,smtp' -Vx > %s"%(path + "/" + pcap_file, display_filter, tmp_file))
            cmd = cmd1 + " " + cmd2
            print "tsharkIMF: Tshark Command: ", cmd

            os.system(cmd)
            self.file_name = tmp_file
            return tmp_file
        except Exception as E:
            print "tsharkIMF: Exception occurred in IMF parsing ", str(E)

        return None

    def readIMFSMTPPacket (self, filename) :
        with open (filename) as f:
            self.imf_lines = f.readlines()
            return self.imf_lines

    def getIMFFrameNumber (self, lines) :
        print "The first line is: ", lines [0]
        if 'Frame ' in lines [0]:
            pkt_frame = re.search (r'Frame ([0-9]+):.*', lines [0])
            print "The FRAME is: ", pkt_frame.group (1)
            return pkt_frame.group (1)

    def getIMFFrom (self, lines) :
        for line in lines:
            if ' From: ' in line:
                print "getIMFFrom: ", line
                pkt_from = re.search (r' From: .*<(.*)>,.*', line)
                print "The FROM is: ", pkt_from.group (1)
                return pkt_from.group (1)

    def getIMFFromMsisdn (self, lines) :
        for line in lines:
            if ' From: ' in line:
                print "getIMFFromMsisdn: ", line
                pkt_from = re.search (r' From: .*?(.*),.*', line)
                print "The FROM is: ", pkt_from.group (1)
                return pkt_from.group (1)

    def getIMFTo (self, lines) :
        for line in lines:
            if ' To: ' in line:
                print "getIMFTo: ", line
                pkt_to = re.search (r' To: (.*),.*', line)
                print "The TO is: ", pkt_to.group (1)
                return pkt_to.group (1)

    def getIMFContentTypeImage (self, lines) :
        for line in lines:
            if 'Content-Type: image' in line:
                pkt_ctype = re.search(r'(Content-Type: image.* name=(.*))\\r\\n', line)
                print "", pkt_ctype.group (1)
                print "The image name is: ", pkt_ctype.group (2)
                return pkt_ctype.group (2)

    def getIMFContentTypeImageRCS (self, lines) :
        for line in lines:
            if 'Content-Type:image' in line:
                pkt_ctype = re.search(r'(Content-Type:image.*Name=(.*))\\r\\n', line)
                print "", pkt_ctype.group (1)
                print "The image name is: ", pkt_ctype.group (2)
                return pkt_ctype.group (2)

    def getIMFContentDispositionAttachment (self, lines) :
        for line in lines:
            if 'Content-Disposition: attachment' in line:
                pkt_cdisp = re.search(r'(Content-Disposition: attachment.* filename=(.*))\\r\\n', line)
                print "", pkt_cdisp.group (1)
                print "The image name is: ", pkt_cdisp.group (2)
                return pkt_cdisp.group (2)

    def getSMTPResponseCode (self, lines) :
        for line in lines:
            if 'Response code: ' in line:
                pkt_rcode = re.search(r'(Response code: (.*))', line)
                print "", pkt_rcode.group (1)
                print "The SMTP response is: ", pkt_rcode.group (2)
                return pkt_rcode.group (2)

    def validateIMFMessage (self, validate_args, prt = []):
        status = True
        for key in validate_args:
            value = validate_args[key]

            if key == 'IMF_FROM_MSISDN':
                print "imf_message_validation: validateIMFMessage: Checking for: ", key
                actual_value = self.getIMFFromMsisdn (self.imf_lines)
                print "imf_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "imf_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'IMF_FROM':
                print "imf_message_validation: validateIMFMessage: Checking for: ", key
                actual_value = self.getIMFFrom (self.imf_lines)
                print "imf_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "imf_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'IMF_TO':
                print "imf_message_validation: validateIMFMessage: Checking for: ", key
                actual_value = self.getIMFTo (self.imf_lines)
                print "imf_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "imf_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'IMF_CONTENT_TYPE_IMAGE':
                print "imf_message_validation: validateIMFMessage: Checking for: ", key
                actual_value = self.getIMFContentTypeImage (self.imf_lines)
                print "imf_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "imf_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'IMF_CONTENT_TYPE_IMAGE_RCS':
                print "imf_message_validation: validateIMFMessage: Checking for: ", key
                actual_value = self.getIMFContentTypeImageRCS (self.imf_lines)
                print "imf_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "imf_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'IMF_CONTENT_DISPOSITION_ATTACH':
                print "imf_message_validation: validateIMFMessage: Checking for: ", key
                actual_value = self.getIMFContentDispositionAttachment (self.imf_lines)
                print "imf_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "imf_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

        return status

    def validateSMTPMessage (self, validate_args, prt = []):
        status = True
        for key in validate_args:
            value = validate_args[key]

            if key == 'SMTP_RESPONSE_CODE':
                print "imf_message_validation: validateSMTPMessage: Checking for: ", key
                actual_value = self.getSMTPResponseCode (self.imf_lines)
                print "imf_message_validation: validateSMTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "imf_message_validation: validateSMTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

        return status

if __name__ == '__main__':
    image_name = '20160817_162132.jpeg'
    msisdn     = '16194905181'
    #emailid    = "rcsprodtmo@gmail.com"
    emailid    = "14253196810"
    pcap_file  = "tc26_mmse_1.pcap"
    #pcap_file  = "tc5_d11.pcap"

    # Instatiate the class object
    class_obj = IMFMessageValidation ()

    #'''
    dfilter = "imf contains \"" + emailid + "\" and not tcp.analysis.retransmission"
    print "The display filter is: ", dfilter

    # Use tshark to identify EXACTLY ONE PACKET with necessary display filter
    # tshark writes to class_obj.file_name
    if class_obj.tsharkIMFSMTP ('/tmp', pcap_file, dfilter) == None :
        print "Damn!"

    #class_obj.file_name = "/tmp/2016-12-06_18-16-33.txt"

    # Read the text file that packet info dumped by tshark
    # All packet data from text file will be read in to class_obj.imf_lines
    class_obj.readIMFSMTPPacket(class_obj.file_name)

    class_obj.getIMFFrameNumber (class_obj.imf_lines)
    #class_obj.getIMFFrom (class_obj.imf_lines)
    class_obj.getIMFFromMsisdn (class_obj.imf_lines)
    class_obj.getIMFTo (class_obj.imf_lines)
    class_obj.getIMFContentTypeImage (class_obj.imf_lines)
    class_obj.getIMFContentDispositionAttachment (class_obj.imf_lines)

    validateParameters = OrderedDict([
        #('IMF_FROM', emailid),
        ('IMF_FROM_MSISDN', emailid),
        ('IMF_TO', msisdn),
        ('IMF_CONTENT_TYPE_IMAGE_RCS', image_name)])
        #('IMF_CONTENT_DISPOSITION_ATTACH', image_name)])

    msg_body = []
    result = class_obj.validateIMFMessage (validateParameters, msg_body)
    '''

    framenum   = "7610"
    streamix   = "6137"
    pcap_file  = "tc5_d11.pcap"
    resp_code  = "Requested mail action okay, completed"

    dfilter = "frame.number > " + framenum + " and tcp.stream==" + streamix + " and not tcp.analysis.flags and smtp.response.code==250"
    print "The display filter is: ", dfilter

    # Use tshark to identify EXACTLY ONE PACKET with necessary display filter
    # tshark writes to class_obj.file_name
    if class_obj.tsharkIMFSMTP ('/tmp',  pcap_file, dfilter) == None :
        print "Damn!"

    #class_obj.file_name = "/tmp/2016-11-28_20-19-15.txt"

    class_obj.readIMFSMTPPacket(class_obj.file_name)
    class_obj.getSMTPResponseCode (class_obj.imf_lines)

    validateParameters = OrderedDict([
        ('SMTP_RESPONSE_CODE', resp_code)])

    msg_body = []
    result = class_obj.validateSMTPMessage (validateParameters, msg_body)
    '''
