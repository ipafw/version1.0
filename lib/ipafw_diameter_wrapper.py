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

from ipafw_diameter_proto                  import DiameterMessageValidation

class ipafwDiameter () :

    def __init__ (self, ipafw_self) :
        self.ipafw = ipafw_self

        self.dia_mv_instance  = DiameterMessageValidation ()

    def getDiameterHeaderValue (self, pkt, in_dict, protocol_check_dict) :
        pstr = "frameworkTestDriver: getDiameterHeaderValue: "

        if hasattr (pkt, 'diameter') == False :
            return None

        hdr_name = protocol_check_dict ["HEADER_NAME"]

        if hdr_name == "Command-Code" :
            return self.dia_mv_instance.getCommandCode (pkt)

        if hdr_name == "User-Identity-MSISDN" :
            return self.dia_mv_instance.getDiameterMSISDN (pkt)

        if hdr_name == "Session-Id" :
            return self.dia_mv_instance.getDiameterSessionID (pkt)

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

