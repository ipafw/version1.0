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

class ipafwParsePacket () :

    def __init__ (self, ipafw_self) :
        self.ipafw = ipafw_self

    def parsePacket (self, current_validation, in_dict, pkt) :
        pstr = "frameworkTestDriver: parsePacket: "
        #current_validation = in_dict ["VALIDATIONS"][validation ["ORDER"]]["VALIDATIONS"]

        if "PROTOCOL_CHECK" in current_validation ["PARSE_PACKET"] :
            protocol_check_list = current_validation ["PARSE_PACKET"]["PROTOCOL_CHECK"]
            print pstr, "PARSE PROTOCOL CHECK: ", protocol_check_list

            result = self.ipafw.pchk.doProtocolCheck (pkt, in_dict, protocol_check_list)
            print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"
            if result :
                print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>PARSE PROTOCOL CHECK: PASSED, FRAME: ", pkt.frame_info.number, "\n"
                return True
            else :
                print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>PARSE PROTOCOL CHECK: FAILED, FRAME: ", pkt.frame_info.number
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

