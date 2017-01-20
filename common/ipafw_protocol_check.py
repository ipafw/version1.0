import yaml
import pyshark
import time
import os
import re

import pyshark
from robot.api                             import logger
from robot.libraries.BuiltIn               import BuiltIn

from collections                           import OrderedDict

from sip_message_validation                import SipMessageValidation
from http_message_validation               import HTTPMessageValidation
from cmn_Pass_Fail                         import Pass_Fail,html_fail,html_pass,FAIL,PASS
from parse_global_variables                import parse_TcVariable, ParseGlobalVariable

from ipafw_mmse_proto                      import MMSEMessageValidation

class ipafwProtocolCheck () :

    def __init__ (self, ipafw_self) :
        self.ipafw = ipafw_self

        self.mmse_mv_instance = MMSEMessageValidation ()

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
                    hdr_value   = self.ipafw.frame.getFrameHeaderValue (pkt, in_dict, protocol_check_dict)

                if protocol_check_dict ["LAYER"] == "http" :
                    hdr_value   = self.ipafw.http.getHTTPHeaderValue (pkt, in_dict, protocol_check_dict)

                if protocol_check_dict ["LAYER"] == "mmse" :
                    hdr_value   = self.ipafw.mmse.getMMSEHeaderValue (pkt, in_dict, protocol_check_dict)

                if protocol_check_dict ["LAYER"] == "diameter" :
                    hdr_value   = self.ipafw.dia.getDiameterHeaderValue (pkt, in_dict, protocol_check_dict)

                if "SETVAR" in protocol_check_dict :
                    hdr_set_var = protocol_check_dict ["SETVAR"]
                    in_dict ["VARIABLES"][hdr_set_var] = hdr_value

                #NOTE: Check this below 'if' condition with 'MATCH' value in validation file
                if "MATCH" in protocol_check_dict :
                    if hdr_value == None :
                        return None

                    match = protocol_check_dict ["MATCH"]
                    print pstr, "MATCH VALUE IS: ", match

                    if "GETVAR" in protocol_check_dict :
                        hdr_get_var = protocol_check_dict ["GETVAR"]
                        hdr_get_val = in_dict ["VARIABLES"][hdr_get_var]
                        print pstr, "HEADER GETVAR IS: ", hdr_get_var, " HEADER GET VALUE IS: ", hdr_get_val
                    elif "VALUE" in protocol_check_dict :
                        hdr_get_val = protocol_check_dict ["VALUE"]
                        print pstr, "HEADER VALUE IS: ", hdr_get_val

                    if match == "exists" :
                        if hdr_get_val in hdr_value :
                            result = result + 1
                            print pstr, "HEADER NAME: ", protocol_check_dict ["HEADER_NAME"], " MATCHED: ", hdr_value
                        else :
                            print pstr, "HEADER NAME: ", protocol_check_dict ["HEADER_NAME"], " NOT MATCHED: ", hdr_value
                            continue

                    if match == "equals" :
                        if hdr_get_val == hdr_value :
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

if __name__ == '__main__':

    '''
    obj.resetTestContext ()
    print " Reset MSISDN A current dict: ", obj.current_dict ["YAML_VARIABLE_INPUTS"][0]["YAML_MSISDN_A"]
    print " Reset MSISDN A context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_MSISDN_A"]
    print " Reset IMSI A context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_IMSI_A"]
    print " Reset MSISDN B context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_MSISDN_B"]
    print " Reset IMSI B context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_IMSI_B"]
    '''
    pass

