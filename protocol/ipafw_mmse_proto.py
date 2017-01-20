from cmn_Pass_Fail import Pass_Fail,html_fail,html_pass,FAIL,PASS
from robot.libraries.BuiltIn import BuiltIn
import re
from robot.api import logger

PASS = '<b style="color:green">PASS</b>'
FAIL = '<b style="color:red">FAILED</b>'

MMSE_PASS = '<b style="color:green">PASS</b>'
MMSE_FAIL = '<b style="color:red">FAILED OR MISSED PACKETS</b>'

class MMSEMessageValidation:
    def getMMSEMessageType (self, packet):
        return packet.mmse.message_type

    def getMMSETransactionID (self, packet):
        return packet.mmse.transaction_id

    def getMMSEMessageID (self, packet):
        return packet.mmse.message_id

    def getMMSEFrom (self, packet):
        actual_value_full = packet.mmse.From
        print "MMSEMessageValidation: getMMSEFrom: ", actual_value_full
        actual_value      = re.search (r'(.*?)[(/TYPE=PLMN)]', str(actual_value_full)).group(1)
        actual_value      = actual_value.replace('+', '')
        return actual_value

    def getMMSEEmailFrom (self, packet):
        actual_value = packet.mmse.From
        print "MMSEMessageValidation: getMMSEFrom: ", actual_value
        return actual_value

    def getMMSETo (self, packet):
        actual_value_full = packet.mmse.To
        actual_value      = re.search (r'(.*?)/TYPE=PLMN', str(actual_value_full)).group(1)
        actual_value      = actual_value.replace('+', '')
        return actual_value

    def getMMSEEmailTo (self, packet):
        actual_value = packet.mmse.To
        print "MMSEMessageValidation: getMMSEEmailTo: ", actual_value
        return actual_value

    def getMMSEMessageSize (self, packet):
        return packet.mmse.message_size

    def getMMSEExpiry (self, packet):
        return packet.mmse._all_fields ['mmse.expiry.rel']

    def getMMSEContentLocation (self, packet):
        return packet.mmse.content_location

    def getMMSEStatus (self, packet):
        return packet.mmse.status

    def getMMSEResponseStatus (self, packet):
        return packet.mmse.response_status

    def getMMSEResponseText (self, packet):
        return packet.mmse.response_text

    def getMMSEReadStatus (self, packet):
        return packet.mmse.read_status

    def getMMSERetrieveStatus (self, packet):
        return packet.mmse.retrieve_status

    def getMMSERetrieveText (self, packet):
        return packet.mmse.retrieve_text

    def getMMSESMPPBind (self, packet):
        return packet.smpp.source_addr

    def getMMSESMPPDestAddr (self, packet):
        return packet.smpp.destination_addr

    def validateMMSEMessage(self, packet, validate_args, prt = []):
	status = True
        for key in validate_args:
            value = validate_args[key]
            all_mmse_fields = packet.mmse._all_fields

            if key == 'MESSAGE_TYPE':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEMessageType (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'TRANSACTION_ID':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSETransactionID (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'MESSAGE_ID':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEMessageID (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'FROM':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEFrom (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if str (value) in actual_value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'EMAIL_FROM':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEEmailFrom (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if str (value) in actual_value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'TO':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSETo (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value in value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'EMAIL_TO':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEEmailTo (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if str (value) in actual_value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'MESSAGE_SIZE':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEMessageSize (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'CONTENT_LOCATION':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEContentLocation (packet.mmse)
                print "mmse_message_validation: validateMMSEMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'SMPPBIND':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSESMPPBind (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", str (actual_value)
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + str (actual_value)
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'SMPPDESTADDR':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSESMPPDestAddr (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", str (actual_value)
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + str (actual_value)
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'STATUS':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEStatus (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", str (actual_value)
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + str (actual_value)
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'RESPONSE_STATUS':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEResponseStatus (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", str (actual_value)
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + str (actual_value)
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'RESPONSE_TEXT':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEResponseText (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", str (actual_value)
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + str (actual_value)
                if value in actual_value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'READ_STATUS':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSEReadStatus (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", str (actual_value)
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + str (actual_value)
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'RETRIEVE_STATUS':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSERetrieveStatus (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", str (actual_value)
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + str (actual_value)
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'RETRIEVE_TEXT':
                print "mmse_message_validation: validateMMSEMessage: Checking for :", key
                actual_value = self.getMMSERetrieveText (packet)
                print "mmse_message_validation: validateMMSEMessage: actual_value", str (actual_value)
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + str (actual_value)
                if actual_value == value :
                    print "mmse_message_validation: validateMMSEMessage: print_value", print_value
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
            #message2 = message1 + " - " + html_pass
            message2 = message1 + " - " + MMSE_PASS
        elif result == False:
            message1 = '<b style="color:red">%s</b> ' % message
            #message2 = message1 + " - " + html_fail
            message2 = message1 + " - " + MMSE_FAIL
        elif result == 'MsgBody':
            for i in message:
                message2 = message2 + i + '\n'
                #if 'Expected' in i:
                    #message2 = message2+i+'  -  '+html_fail+'\n'
                #else:
                    #message2 = message2+i+'  -  '+html_pass+'\n'
        return message2

