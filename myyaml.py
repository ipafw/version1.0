import yaml
import pyshark
import time
import os
import re

import pyshark
from robot.api                  import logger
from robot.libraries.BuiltIn    import BuiltIn

from collections                import OrderedDict

from sip_message_validation     import SipMessageValidation
from http_message_validation    import HTTPMessageValidation
from cmn_Pass_Fail              import Pass_Fail,html_fail,html_pass,FAIL,PASS
from parse_global_variables     import parse_TcVariable, ParseGlobalVariable
from mmse_support_functions     import MMSESupportFunctions
from mmse_message_validation    import MMSEMessageValidation
from http_message_validation    import HTTPMessageValidation


class frameworkTestDriver () :

    def __init__ (self, yaml_file):
        self.current_dict = {}
        self.context_dict = {}
        self.yaml_file    = yaml_file

        self.setTestContext ()

    def setTestContext (self) :

        self.context_dict ["VARIABLES"]   = {}
        self.context_dict ["VALIDATIONS"] = {}
        self.result1                      = []
        self.message                      = []
        self.pass_fail_result             = []

        self.current_dict = self.readYAML (self.yaml_file)
        #print "yaml dict: ", self.current_dict

        self.printYAMLFileInputs (self.current_dict)
        self.printYAMLVariableInputs (self.current_dict)
        self.printYAMLTestValidations (self.current_dict)

        self.context_dict ["YAML_FILE_INPUTS"]     = self.current_dict ["YAML_FILE_INPUTS"]
        self.context_dict ["TEST_VALIDATIONS"]     = self.current_dict ["TEST_VALIDATIONS"]
        self.context_dict ["READ_PCAP"]            = self.current_dict ["READ_PCAP"]

    def resetTestContext (self, yaml_file=None) :
        for key in self.current_dict.keys () :
            del self.current_dict [key]

        for key in self.context_dict.keys () :
            del self.context_dict [key]

        if yaml_file != None :
            self.yaml_file = yaml_file

        self.setTestContext ()

    def readYAML (self, yaml_file) :
        pstr = "frameworkTestDriver: readYAML: "
        with open (yaml_file, "r") as fh:
            try:
                self.yaml_dict = yaml.load (fh)
                #print (self.yaml_dict)
            except yaml.YAMLError as E:
                print (pstr, str(E))
                return None

        #self.current_dict = self.yaml_dict
        return self.yaml_dict

    def printYAMLFileInputs (self, in_dict) :
        pstr = "frameworkTestDriver: printYAMLFileInputs: "
        for yaml_input in in_dict ["YAML_FILE_INPUTS"] :
            print pstr, "file name: ", yaml_input ["FILE_NAME"]

            print pstr, "name space: ", yaml_input ["NAME_SPACE"]

            in_dict [yaml_input ["NAME_SPACE"]] = self.readYAML (yaml_input ["FILE_NAME"])

            print pstr, "YAML FILE INPUTS for: ", yaml_input ["FILE_NAME"], ": ", in_dict [yaml_input ["NAME_SPACE"]]

    def printYAMLVariableInputs (self, in_dict) :
        pstr = "frameworkTestDriver: printYAMLVariableInputs: "

        for yaml_variable in in_dict ["YAML_VARIABLE_INPUTS"] :
            self.evalSetVariable (yaml_variable, in_dict)

            '''
            print pstr, "variable: ", yaml_variable ["SETVAR"]

            var, keys = yaml_variable ["SETVAR"].split ('=$')
            #print pstr, "the var is: ", var

            keys_list = keys.split (':')
            #print pstr, "key list first elem: ", keys_list [0]

            if in_dict [keys_list [0]] != None :
                tmp_dict = in_dict
                for key in keys.split (':') :
                    #print pstr, "\tkey is: ", key
                    #print pstr, "\tdict now is ", tmp_dict [key]
                    tmp_dict = tmp_dict [key]

                yaml_variable [var] = str (tmp_dict)

                # Set the evaluated variables directly in context_dict
                self.context_dict ["YAML_VARIABLE_INPUTS"][var] = str (tmp_dict)
                #print pstr, var, "value is: " , self.context_dict ["YAML_VARIABLE_INPUTS"][var]
                #print pstr, var, "value is: " , in_dict ["YAML_VARIABLE_INPUTS"][0]
            else :
                print pstr, "format issue"
            '''

        #print "other name: NGN: ", in_dict ["NGN"]
        #print "other name: TC00001: ", in_dict ["TC00001"]

    def evalSetVariable (self, yaml_variable, in_dict) :
        pstr = "frameworkTestDriver: evalSetVariable: "

        print pstr, "variable: ", yaml_variable ["SETVAR"]

        var, keys = yaml_variable ["SETVAR"].split ('=$')
        #print pstr, "the var is: ", var

        keys_list = keys.split (':')
        #print pstr, "key list first elem: ", keys_list [0]

        prefix = keys_list [0]
        if in_dict [prefix] != None :
            tmp_dict = in_dict
            #for key in keys.split (':') :
            for key in keys_list :
                #print pstr, "\tkey is: ", key
                #print pstr, "\tdict now is ", tmp_dict [key]
                tmp_dict = tmp_dict [key]

            yaml_variable [var] = str (tmp_dict)

            # Set the evaluated variables directly in context_dict
            self.context_dict ["VARIABLES"][var] = str (tmp_dict)
            #print pstr, var, "value is: " , self.context_dict ["YAML_VARIABLE_INPUTS"][var]
            #print pstr, var, "value is: " , in_dict ["YAML_VARIABLE_INPUTS"][0]
        else :
            print pstr, "format issue"

    def printYAMLTestValidations (self, in_dict) :
        pstr = "frameworkTestDriver: printYAMLTestValidations: "
        for validation in in_dict ["TEST_VALIDATIONS"] :
            print pstr, "order: ", validation ["ORDER"]

            print pstr, "\tconfig data:", validation ["CONFIG"]

            print pstr, "\tpass criteria:", validation ["PASS_CRITERIA"]


    def parseYAMLTestValidation (self, in_dict) :
        pstr = "frameworkTestDriver: parseYAMLTestValidations: "
        for validation in in_dict ["TEST_VALIDATIONS"] :
            print pstr, "order: ", validation ["ORDER"]

            print pstr, "\tconfig data:", validation ["CONFIG"]

            self.context_dict ["VALIDATIONS"][validation ["ORDER"]] = self.readYAML (validation ["CONFIG"]["FILE_NAME"])

            if "SETVAR" in validation ["CONFIG"] :
                self.evalSetVariable (validation ["CONFIG"], in_dict)

            print pstr, "\tpass criteria:", validation ["PASS_CRITERIA"]

    def readPcap (self, in_dict, display_filter) :
        pstr = "frameworkTestDriver: readPcap: "

        pcap_location  = in_dict ["VARIABLES"]["YAML_PCAP_LOCATION"]
        pcap_file      = pcap_location + "/" + in_dict ["VARIABLES"]["YAML_PCAP_FILE"]

        in_dict ["PACKET_CAPTURE"] = pyshark.FileCapture(pcap_file, display_filter = display_filter)

    def startYAMLTestValidation (self, in_dict) :
        pstr           = "frameworkTestDriver: startYAMLTestValidation: "
        frame_number   = None
        frame_position = None

        self.mmse_mv_instance = MMSEMessageValidation ()
        self.http_mv_instance = HTTPMessageValidation ()
        self.mmse_sf_instance = MMSESupportFunctions  ()

        for validation in in_dict ["TEST_VALIDATIONS"] :
            print pstr, "order: ", validation ["ORDER"]

            print pstr, "\tconfig data:", validation ["CONFIG"]

            print pstr, "\tpass criteria:", validation ["PASS_CRITERIA"]

            if "START_FRAME" in validation ["CONFIG"] :
                if "GETVAR" in validation ["CONFIG"]["START_FRAME"] and \
                   "MATCH" in validation ["CONFIG"]["START_FRAME"] :
                    frame_get_var = validation ["CONFIG"]["START_FRAME"]["GETVAR"]
                    frame_number  = in_dict ["VARIABLES"][frame_get_var]
                    frame_position = validation ["CONFIG"]["START_FRAME"]["MATCH"]

            print pstr, "PACKET PARSING TO START FROM: %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%: ", frame_number

            self.startYAMLTestValidationPerFile (validation, in_dict, frame_number, frame_position)

        self.message.append(self.mmse_mv_instance.updateResults(True,"----------------------------------------------------"))

    def startYAMLTestValidationPerFile (self, validation_per_file, in_dict, frame_number, frame_position) :
        pstr = "frameworkTestDriver: startYAMLTestValidationPerFile: "
        validations = in_dict ["VALIDATIONS"][validation_per_file ["ORDER"]]["VALIDATIONS"]
        print pstr, "ALL VALIDATION IN GIVEN YAML FILE: ", validations

        for current_validation in validations :

            print pstr, "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$VALIDATION PER FILE PER KEY IS: ", current_validation

            print "*****************************************************************\n\n"

            if "IDENTIFY_PACKET" in current_validation :
                self.pkt = self.identifyPacket (current_validation, in_dict, frame_number, frame_position)
                if self.pkt == None :
                    print pstr, "FAILED TO IDENTIFY PACKET DESCRIBED IN: ", validation_per_file ["CONFIG"]["FILE_NAME"]
                    return

            print "*****************************************************************\n\n"

            if "PARSE_PACKET" in current_validation :
                if self.parsePacket (current_validation, in_dict, self.pkt) == None:
                    print pstr, "FAILED TO PARSE PACKET DESCRIBED IN: ", validation_per_file ["CONFIG"]["FILE_NAME"]
                    return

            print "*****************************************************************\n\n"

            if "VALIDATE_PACKET" in current_validation :
                if self.validatePacket (current_validation, in_dict, self.pkt) == None:
                    print pstr, "FAILED TO VALIDATE PACKET DESCRIBED IN: ", validation_per_file ["CONFIG"]["FILE_NAME"]
                    return

            print "*****************************************************************\n\n"

            if "POST_VALIDATION" in current_validation :
                if self.postValidation (current_validation, in_dict, self.pkt) == None:
                    print pstr, "FAILED TO PERFORM POST VALIDATION DESCRIBED IN: ", validation_per_file ["CONFIG"]["FILE_NAME"]
                    return

    def identifyPacket (self, current_validation, in_dict, frame_number=None, position=None) :
        pstr = "frameworkTestDriver: identifyPacket: "
        #current_validation = in_dict ["VALIDATIONS"][validation ["ORDER"]]["VALIDATIONS"]

        cap = in_dict ["PACKET_CAPTURE"]

        pkt = None
        for pkt in cap :

            pkt_frame_number = pkt.frame_info.number

            if frame_number != None :
                if int (pkt_frame_number) <= int (frame_number) :
                    continue

            if "IP_CHECK" in current_validation ["IDENTIFY_PACKET"] :
                #ip_check_list = in_dict ["VALIDATIONS"][validation ["ORDER"]]["VALIDATIONS"]["IDENTIFY_PACKET"]["IP_CHECK"]
                ip_check_list = current_validation ["IDENTIFY_PACKET"]["IP_CHECK"]

                #print pstr, "IP CHECK: ", validation ["VALIDATIONS"]["IDENTIFY_PACKET"]["IP_CHECK"]
                print pstr, "IDENTIFY IP CHECK LIST: ", ip_check_list

                result = self.doIPCheck (pkt, in_dict, ip_check_list)
                print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
                if result :
                    print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>IDENTIFY IP CHECK: PASSED, FRAME: ", pkt.frame_info.number, "\n"
                else :
                    print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>IDENTIFY IP CHECK: FAILED, FRAME: ", pkt.frame_info.number, " CONTINUE IP CHECKS\n"
                    continue

            if "PROTOCOL_CHECK" in current_validation ["IDENTIFY_PACKET"] :
                protocol_check_list = current_validation ["IDENTIFY_PACKET"]["PROTOCOL_CHECK"]
                print pstr, "IDENTIFY PROTOCOL CHECK: ", protocol_check_list

                result = self.doProtocolCheck (pkt, in_dict, protocol_check_list, True)
                print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
                if result :
                    print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>IDENTIFY PROTOCOL CHECK: PASSED, FRAME: ", pkt.frame_info.number, "\n"
                    return pkt
                else :
                    print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>IDENTIFY PROTOCOL CHECK: FAILED, FRAME: ", pkt.frame_info.number, " CONTINUE PROTOCOL CHECKS\n"
                    continue

        # Unable to identify the packet
        return None

    def parsePacket (self, current_validation, in_dict, pkt) :
        pstr = "frameworkTestDriver: parsePacket: "
        #current_validation = in_dict ["VALIDATIONS"][validation ["ORDER"]]["VALIDATIONS"]

        if "PROTOCOL_CHECK" in current_validation ["PARSE_PACKET"] :
            protocol_check_list = current_validation ["PARSE_PACKET"]["PROTOCOL_CHECK"]
            print pstr, "PARSE PROTOCOL CHECK: ", protocol_check_list

            result = self.doProtocolCheck (pkt, in_dict, protocol_check_list)
            print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
            if result :
                print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>PARSE PROTOCOL CHECK: PASSED, FRAME: ", pkt.frame_info.number, "\n"
                return True
            else :
                print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>PARSE PROTOCOL CHECK: FAILED, FRAME: ", pkt.frame_info.number
                return None

    def validatePacket (self, current_validation, in_dict, pkt) :
        pstr = "frameworkTestDriver: validatePacket: "
        #current_validation = in_dict ["VALIDATIONS"][validation ["ORDER"]]["VALIDATIONS"]
        self.msg_body = []
        result        = False

        print pstr, "VALIDATE PACKET DICTIONARY LIST: ", current_validation ["VALIDATE_PACKET"]

        msg = current_validation ["DESCRIPTION"]

        print pstr,  msg

        for validate_dict in current_validation ["VALIDATE_PACKET"] :
            print pstr, "VALIDATE DICT: ", validate_dict

            validate_parameters = OrderedDict()
            for dict_elem in validate_dict ["DICTS"] :
                print pstr, "DICT ELEM IS: ", dict_elem

                for key in dict_elem.keys () :
                    print pstr, "KEY IS: ", key, " DICT ELEM KEY IS: ", dict_elem [key]
                    if key == "key" :
                        param_key = dict_elem [key]
                    if key == "value" :
                        param_val = dict_elem [key]
                    if key == "GETVAR" :
                        param_val = in_dict ["VARIABLES"][dict_elem [key]]

                print pstr, "PARAM KEY: ", param_key, " PARAM VAL: ", param_val

                validate_parameters [param_key] = param_val

            print pstr, "ORDERED VALIDATE PARAM DICT: ", validate_parameters

            if validate_dict ["LAYER"] == "http" :
                result = self.http_mv_instance.validateHTTPMessage(pkt, validate_parameters, self.msg_body)

            if validate_dict ["LAYER"] == "mmse" :
                result = self.mmse_mv_instance.validateHTTPMessage(pkt, validate_parameters, self.msg_body)

            self.result1.append(msg)
            self.message.append(self.http_mv_instance.updateResults(result, msg))
            self.message.append(self.http_mv_instance.updateResults('MsgBody',self.msg_body))
            self.pass_fail_result.append(PASS if result == True else msg)

        print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"

        print pstr, "VALIDATE PACKET RESULT: ", self.result1
        print pstr, "VALIDATE PACKET MESSAGE: ", self.message

        if result :
            print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>VALIDATE PACKET CHECK: PASSED, FRAME: ", pkt.frame_info.number, "\n"
            return True
        else :
            print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>VALIDATE PACKET CHECK: FAILED, FRAME: ", pkt.frame_info.number
            return None

    def postValidation (self, current_validation, in_dict, pkt) :
        pstr = "frameworkTestDriver: postValidation: "
        #current_validation = in_dict ["VALIDATIONS"][validation ["ORDER"]]["VALIDATIONS"]

        if "PROTOCOL_CHECK" in current_validation ["POST_VALIDATION"] :
            protocol_check_list = current_validation ["POST_VALIDATION"]["PROTOCOL_CHECK"]
            print pstr, "POST_VALIDATION PROTOCOL CHECK: ", protocol_check_list

            result = self.doProtocolCheck (pkt, in_dict, protocol_check_list)
            print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
            if result :
                print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>POST_VALIDATION PROTOCOL CHECK: PASSED, FRAME: ", pkt.frame_info.number, "\n"
                return True
            else :
                print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>POST_VALIDATION PROTOCOL CHECK: FAILED, FRAME: ", pkt.frame_info.number
                return None

    def doProtocolCheck (self, pkt, in_dict, protocol_check_list, identify=False) :
        pstr = "frameworkTestDriver: doProtocolCheck: "
        result = 0

        print "\t-----------------------------------------------------------------\n"

        result_max = len (protocol_check_list)

        for protocol_check_dict in protocol_check_list :
            print pstr, "PROTOCOL CHECK DICT: ", protocol_check_dict

            ptype = protocol_check_dict ["TYPE"]

            print pstr, "PROTOCOL CHECK TYPE IS: ", ptype

            if ptype == "method_match" :
                if protocol_check_dict ["LAYER"] == "mmse" :
                    if hasattr (pkt, "mmse") == False:
                        return False

                    if hasattr (pkt.mmse, "message_type") == False:
                        return False

                    mname = protocol_check_dict ["METHOD_NAME"]
                    mID   = protocol_check_dict ["METHOD_ID"]
                    packet_mID = self.mmse_mv_instance.getMMSEMessageType (pkt)

                    if packet_mID == mID :
                        result = result + 1
                        print pstr, "Method name: ", mname, " MATCH FOUND"
                        print pstr, "frame number is: ", pkt.frame_info.number, "result: ", result
                    else :
                        print pstr, "Method name: ", mname, " MATCH NOT FOUND"
                        return False

            elif ptype == "parse_header" :
                if protocol_check_dict ["LAYER"] == "frame" :
                    hdr_value   = self.getFrameHeaderValue (pkt, in_dict, protocol_check_dict)

                if protocol_check_dict ["LAYER"] == "http" :
                    hdr_value   = self.getHTTPHeaderValue (pkt, in_dict, protocol_check_dict)

                if protocol_check_dict ["LAYER"] == "mmse" :
                    hdr_value   = self.getMMSEHeaderValue (pkt, in_dict, protocol_check_dict)

                if "SETVAR" in protocol_check_dict :
                    hdr_set_var = protocol_check_dict ["SETVAR"]
                    in_dict ["VARIABLES"][hdr_set_var] = hdr_value

                if "GETVAR" in protocol_check_dict :
                    hdr_get_var = protocol_check_dict ["GETVAR"]
                    hdr_get_val = in_dict ["VARIABLES"][hdr_get_var]
                    print pstr, "HEADER GETVAR IS: ", hdr_get_var, " HEADER GET VALUE IS: ", hdr_get_val

                    if hdr_get_val in hdr_value :
                        result = result + 1

                        print pstr, "HEADER NAME: ", protocol_check_dict ["HEADER_NAME"], " MATCHED: ", hdr_value
                    else :
                        print pstr, "HEADER NAME: ", protocol_check_dict ["HEADER_NAME"], " NOT MATCHED: ", hdr_value
                        continue


        # We matched necessary src/dst checks. Skip rest of the packets
        # Check results, only for IDENTIFY_PACKET section of PROTOCOL_CHECKs
        if identify :
            if result == result_max :
                print pstr, "result: ", result, " matched with result_max: ", result_max
                print pstr, "frame number is: ", pkt.frame_info.number
                return True

            print "\t-----------------------------------------------------------------\n"

            return False
        else :
            return True

    def getFrameHeaderValue (self, pkt, in_dict, protocol_check_dict) :
        pstr = "frameworkTestDriver: getFrameHeaderValue: "

        hdr_name = protocol_check_dict ["HEADER_NAME"]

        if hdr_name == "FRAME NUMBER" :
            return pkt.frame_info.number

    def getHTTPHeaderValue (self, pkt, in_dict, protocol_check_dict) :
        pstr = "frameworkTestDriver: getHTTPHeaderValue: "

        hdr_name = protocol_check_dict ["HEADER_NAME"]

        if hdr_name == "MSISDN" :
            return self.http_mv_instance.getMSISDN (pkt.http)

    def getMMSEHeaderValue (self, pkt, in_dict, protocol_check_dict) :
        pstr = "frameworkTestDriver: getMMSEHeaderValue: "
        if hasattr (pkt, "mmse") == False :
            return None

        hdr_name = protocol_check_dict ["HEADER_NAME"]

        if hdr_name == "X-Mms-Transaction-ID" :
            return self.mmse_mv_instance.getMMSETransactionID (pkt)

        if hdr_name == "Message-ID" :
            return self.mmse_mv_instance.getMMSEMessageID (pkt)

    def doIPCheck (self, pkt, in_dict, ip_check_list) :
        pstr = "frameworkTestDriver: doIPCheck: "
        result = 0

        print "\t-----------------------------------------------------------------\n"

        result_max = len (ip_check_list)

        for ip_check_dict in ip_check_list :
            print pstr, "IP CHECK DICT: ", ip_check_dict

            ip_get_var = ip_check_dict ["GETVAR"]
            print pstr, "IP VARIABLE GETVAR: ", ip_get_var

            ip_var     = in_dict ["VARIABLES"][ip_get_var]
            print pstr, "IP VARIABLE VALUE: ", ip_var

            print pstr, "IP CHECK TYPE IS: ", ip_check_dict ["TYPE"]

            if ip_check_dict ["TYPE"] == "ip_check_dst" :
                packet_ip = pkt.ip.dst
            elif ip_check_dict ["TYPE"] == "ip_check_src" :
                packet_ip = pkt.ip.src
            else :
                print pstr, "IP CHECK TYPE NOT IN DEFINED FORMAT"
                return False

            print pstr, "PACKET IP IS: ", packet_ip

            print pstr, "IP CHECK MATCH: ", ip_check_dict ["MATCH"]

            if ip_check_dict ["MATCH"] == "exists" :
                if packet_ip in ip_var :
                    result = result + 1
                    print pstr, "IP: ", packet_ip, " IS FOUND IN: ", ip_var
                    print pstr, "frame number is: ", pkt.frame_info.number, "result: ", result
                #    continue
                #else :
                #    continue

            elif ip_check_dict ["MATCH"] == "equals" :
                if packet_ip == ip_var :
                    result = result + 1
                    print pstr, "IP: ", packet_ip, " IS SAME AS: ", ip_var
                    print pstr, "frame number is: ", pkt.frame_info.number, "result: ", result
                #    continue
                #else :
                #    continue
            else :
                print pstr, "IP MATCH VALUE NOT IN DEFINED FORMAT"

        # We matched necessary src/dst checks. Skip rest of the packets
        if result == result_max :
            print pstr, "result: ", result, " matched with result_max: ", result_max
            print pstr, "frame number is: ", pkt.frame_info.number
            return True

        print "\t-----------------------------------------------------------------\n"

        '''
        if result_max != result :
            return True
        else :
            return False
        '''
        return False


if __name__ == '__main__':
    #obj = frameworkTestDriver ()
    obj = frameworkTestDriver ("myyaml.yaml")

    print " MSISDN A current dict: ", obj.current_dict ["YAML_VARIABLE_INPUTS"][0]["YAML_MSISDN_A"]
    print " MSISDN A context dict: ", obj.context_dict ["VARIABLES"]["YAML_MSISDN_A"]

    print "The context dict is: ", obj.context_dict

    print " IMSI A current dict: ", obj.current_dict ["YAML_VARIABLE_INPUTS"][1]["YAML_IMSI_A"]
    print " IMSI A context dict: ", obj.context_dict ["VARIABLES"]["YAML_IMSI_A"]

    print " MSISDN B context dict: ", obj.context_dict ["VARIABLES"]["YAML_MSISDN_B"]

    print " IMSI B context dict: ", obj.context_dict ["VARIABLES"]["YAML_IMSI_B"]

    obj.parseYAMLTestValidation (obj.current_dict)

    print "VALIDATIONS DICT: ", obj.context_dict ["VALIDATIONS"]
    
    # Note these variables will bear only the last test validation that had set them
    # Each test validation may overwrite variables set in TEST_VALIATIONS section
    print " YAML_IP_DST context dict: ", obj.context_dict ["VARIABLES"]["YAML_IP_DST"]
    print " YAML_IP_SRC context dict: ", obj.context_dict ["VARIABLES"]["YAML_IP_SRC"]

    print " PCAP FILE NAME: ", obj.context_dict ["VARIABLES"]["YAML_PCAP_FILE"]
    print " PCAP LOCATION: ", obj.context_dict ["VARIABLES"]["YAML_PCAP_LOCATION"]
    print " PCAP DISPLAY FILTER: ", obj.context_dict ["READ_PCAP"]["OPEN_PCAP_WITH_FILTER"]

    obj.display_filter = obj.context_dict ["READ_PCAP"]["OPEN_PCAP_WITH_FILTER"]
    obj.readPcap (obj.context_dict, obj.display_filter)

    #obj.startYAMLTestValidation (obj.context_dict ["VALIDATIONS"])
    obj.startYAMLTestValidation (obj.context_dict)

    '''
    obj.resetTestContext ()
    print " Reset MSISDN A current dict: ", obj.current_dict ["YAML_VARIABLE_INPUTS"][0]["YAML_MSISDN_A"]
    print " Reset MSISDN A context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_MSISDN_A"]
    print " Reset IMSI A context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_IMSI_A"]
    print " Reset MSISDN B context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_MSISDN_B"]
    print " Reset IMSI B context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_IMSI_B"]
    '''

