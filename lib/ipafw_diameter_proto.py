from cmn_Pass_Fail import Pass_Fail,html_fail,html_pass,FAIL,PASS
from robot.libraries.BuiltIn import BuiltIn
from lxml import etree
from StringIO import StringIO
import re
from robot.api import logger

PASS = '<b style="color:green">PASS</b>'
FAIL = '<b style="color:red">FAIL</b>'

class DiameterMessageValidation ():            
    def getCommandCode (self, packet):
        return packet.diameter.cmd_code

    def getDiameterSessionID (self, packet):
        return packet.diameter.session_id

    def getDiameterSubscriptionID (self, packet):
        return packet.diameter.subscription_id

    def getDiameterSubscriptionIDType (self, packet):
        return packet.diameter.subscription_id_type

    def getDiameterSubscriptionIDData (self, packet):
        return packet.diameter.subscription_id_data

    def getDiameterRequestedAction (self, packet):
        return packet.diameter.requested_action

    def getDiameterUserData (self, packet):
        return packet.diameter.user_data

    def getDiameterExperimentalResultCode (self, packet):
        return packet.diameter.experimental_result_code

    def getDiameterResultCode (self, packet):
        print "getDiameterResultCode: packet diameter attributes: ", dir (packet.diameter)
        print "getDiameterResultCode: packet diameter all fields: ", packet.diameter._all_fields
        if hasattr (packet.diameter, 'result_code') == False :
            return 'NULL'
        else :
            return packet.diameter.result_code

    def getDiameterMSISDN (self, packet):
        msisdn_hex_colon = packet.diameter.msisdn
        msisdn_hex = msisdn_hex_colon.replace (':', '')
        return msisdn_hex.decode ('hex')

    def getDiameterFlagsRequest (self, packet) :
        return packet.diameter.flags_request

    def getDiameterEndToEndID (self, packet) :
        etoeid = packet.diameter.endtoendid
        etoeid_hex = "0x%0*x" % (8, int (etoeid))
        return etoeid_hex

    def getDiameterUserData (self, packet) :
        xmlhex   = packet.diameter.user_data
        xmlascii = xmlhex.replace (':', '').decode ('hex')
        return xmlascii

    def getDiameterUserDataXMLValue (self, packet, xpath) :
        xmlascii = self.getDiameterUserData (packet)
        print "getDiameterXMLAttributeValue: USER DATA TRANSLATED TO XML STRING: ", xmlascii
        xmldoc   = StringIO (xmlascii)
        xtree    = etree.parse (xmldoc)
        xroot    = xtree.xpath (xpath)

        print "getDiameterXMLAttributeValue: ***NOTICE***: Ensure " + xpath + " has an unique path" 
        print "getDiameterXMLAttributeValue: TAG: ", xroot [0].tag
        print "getDiameterXMLAttributeValue: TEXT: ", xroot [0].text

        return xroot [0].text

    def validateDiameterMessage (self, packet, validate_args, prt = []):
	status = True
        for key in validate_args:
            value = validate_args[key]
            all_diameter_fields = packet.diameter._all_fields

            if key == 'SUBSCRIPTION_ID':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getDiameterSubscriptionID (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'SUBSCRIPTION_ID_TYPE':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getDiameterSubscriptionIDType (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'SUBSCRIPTION_ID_DATA':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getDiameterSubscriptionIDData (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if actual_value == value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'REQUESTED_ACTION':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getDiameterRequestedAction (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if str (value) in actual_value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'SESSION_ID':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getDiameterSessionID (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value == actual_value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'EXPERIMENTAL_RESULT_CODE':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getDiameterExperimentalResultCode (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value

                if '2001' in value :
                    value = value + " - DIAMETER_SUCCESS"
                    actual_value = actual_value + " - DIAMETER_SUCCESS"
                if '5106' in value :
                    value = value + " - DIAMETER_ERROR_SUBS_DATA_ABSENT"
                    actual_value = actual_value + " - DIAMETER_ERROR_SUBS_DATA_ABSENT"

                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value == actual_value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'RESULT_CODE':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getDiameterResultCode (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value

                if '2001' in value :
                    value = value + " - DIAMETER_SUCCESS"
                    actual_value = actual_value + " - DIAMETER_SUCCESS"
                if '5106' in value :
                    value = value + " - DIAMETER_ERROR_SUBS_DATA_ABSENT"
                    actual_value = actual_value + " - DIAMETER_ERROR_SUBS_DATA_ABSENT"

                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value == actual_value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'MSISDN':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getDiameterMSISDN (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'CMD_CODE':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getCommandCode (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value == actual_value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'END_TO_END_ID':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getDiameterEndToEndID (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value == actual_value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'USER_DATA':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                actual_value = self.getDiameterUserData (packet)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value == actual_value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'MSISDN_XML':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                xpath = '/Subscriber/RepositoryData/ServiceData/MSISDN'
                actual_value = self.getDiameterUserDataXMLValue (packet, xpath)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'SUBTYPE_XML':
                print "diameter_message_validation: validateDiameterMessage: Checking for: ", key
                xpath = '/Subscriber/RepositoryData/ServiceData/SubType'
                actual_value = self.getDiameterUserDataXMLValue (packet, xpath)
                print "diameter_message_validation: validateDiameterMessage: actual_value", actual_value
                print_value = "\tExpected: " + key + "- " + str(value) + "\t\tActual: " + key + "- " + actual_value
                if value in actual_value :
                    print "diameter_message_validation: validateDiameterMessage: print_value", print_value
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
        return message2

