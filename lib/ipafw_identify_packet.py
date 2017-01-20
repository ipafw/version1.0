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

class ipafwIdentifyPacket () :

    def __init__ (self, ipafw_self) :
        self.ipafw = ipafw_self

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

                result = self.ipafw.ipchk.doIPCheck (pkt, in_dict, ip_check_list)
                print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
                if result :
                    print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>IDENTIFY IP CHECK: PASSED, FRAME: ", pkt.frame_info.number, "\n"
                else :
                    print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>IDENTIFY IP CHECK: FAILED, FRAME: ", pkt.frame_info.number, " CONTINUE IP CHECKS\n"
                    continue

            if "PROTOCOL_CHECK" in current_validation ["IDENTIFY_PACKET"] :
                protocol_check_list = current_validation ["IDENTIFY_PACKET"]["PROTOCOL_CHECK"]
                print pstr, "IDENTIFY PROTOCOL CHECK: ", protocol_check_list

                result = self.ipafw.pchk.doProtocolCheck (pkt, in_dict, protocol_check_list, True)
                print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
                if result :
                    print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>IDENTIFY PROTOCOL CHECK: PASSED, FRAME: ", pkt.frame_info.number, "\n"
                    return pkt
                else :
                    print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>IDENTIFY PROTOCOL CHECK: FAILED, FRAME: ", pkt.frame_info.number, " CONTINUE PROTOCOL CHECKS\n"
                    continue

        # Unable to identify the packet
        return None

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

