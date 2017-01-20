from cmn_Pass_Fail import Pass_Fail,html_fail,html_pass,FAIL,PASS
from robot.libraries.BuiltIn import BuiltIn
import re
from robot.api import logger

PASS = '<b style="color:green">PASS</b>'
FAIL = '<b style="color:red">FAIL</b>'

class SMTPMessageValidation:
    def getIMFSender (self, packet):
        return packet.imf._all_fields ['imf.sender']

    def getIMFMessageID (self, packet):
        return packet.imf._all_fields ['imf.message_id']

    def getIMFContentType (self, packet):
        return packet.imf._all_fields ['imf.content.type']
        
    def getIMFUserAgent (self, packet):
        return packet.imf._all_fields ['imf.user_agent']

    def getIMFExtension (self, packet):
        return packet.imf._all_fields ['imf.extension']

    def getSMTPResponseParameter (self, packet):
        return packet.smtp._all_fields ['smtp.rsp.parameter']

    def getSMTPResponseCode (self, packet):
        return packet.smtp._all_fields ['smtp.response.code']

    def getSMTPResponse (self, packet):
        return packet.smtp._all_fields ['smtp.response']

    def getRecipientEmailID (self, packet) :
        try:
            imf_extension = self.getIMFExtension (packet)
            print "smtp_message_validation: getRecipientEmailID: imf extension: ", imf_extension

            var = re.search (r'To: (.*)', imf_extension)
            print "smtp_message_validation: getRecipientEmailID: val: ", var.group(1)
            return var.group(1)
        except Exception as e:
            print ("\tsmtp_message_validation: getRecipientEmailID: Error while parsing http packet: " + repr(e))

        return ""

    def getIMFmimeContentType (self, packet):
        return packet.imf._all_fields ['mime_multipart.header.content-type']

    def getIMFmimeTo (self, packet):
        return packet.imf.to

    def validateIMFMessage (self, packet, validate_args, prt = []):
        print "smtp_message_validation: validateIMFMessage: IN"
	status = True
        for key in validate_args:
            value = validate_args[key]
            all_imf_fields = packet.imf._all_fields

            if key == 'SENDER':
                actual_value = self.getIMFSender (packet)
                print "smtp_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "smtp_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'MESSAGE_ID':
                actual_value = self.getIMFMessageID (packet)
                print "smtp_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "smtp_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'CONTENT_TYPE':
                actual_value = self.getIMFContentType (packet)
                print "smtp_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value:
                    print "smtp_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'USER_AGENT':
                actual_value = self.getIMFUserAgent (packet)
                print "smtp_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if str (value) in actual_value :
                    print "smtp_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'TO':
                actual_value = self.getRecipientEmailID (packet)
                print "smtp_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if str (value) in actual_value :
                    print "smtp_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'IMF_TO':
                actual_value = self.getIMFmimeTo (packet)
                print "smtp_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if str (value) in actual_value :
                    print "smtp_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'MIME_CONTENT_TYPE':
                actual_value = self.getIMFmimeContentType (packet)
                print "smtp_message_validation: validateIMFMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value:
                    print "smtp_message_validation: validateIMFMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

        print "smtp_message_validation: validateIMFMessage: OUT"
        return status

    def validateSMTPMessage (self, packet, validate_args, prt = []):
        print "smtp_message_validation: validateSMTPMessage: IN"
        status = True
        for key in validate_args:
            value = validate_args[key]
            all_smtp_fields = packet.smtp._all_fields

            if key == 'RESPONSE_CODE':
                actual_value = self.getSMTPResponseCode (packet)
                print "smtp_message_validation: validateSMTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value == actual_value :
                    print "smtp_message_validation: validateSMTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'RESPONSE_MESSAGE':
                actual_value = self.getSMTPResponseParameter (packet)
                print "smtp_message_validation: validateSMTPMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "smtp_message_validation: validateSMTPMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

        print "smtp_message_validation: validateSMTPMessage: OUT"
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

