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

class ipafwMMSE () :

    def __init__ (self, ipafw_self) :
        self.ipafw = ipafw_self

        self.mmse_mv_instance = MMSEMessageValidation ()

    def getMMSEHeaderValue (self, pkt, in_dict, protocol_check_dict) :
        pstr = "frameworkTestDriver: getMMSEHeaderValue: "
        if hasattr (pkt, "mmse") == False :
            return None

        hdr_name = protocol_check_dict ["HEADER_NAME"]

        if hdr_name == "FROM" :
            return self.mmse_mv_instance.getMMSEFrom (pkt)

        if hdr_name == "TO" :
            return self.mmse_mv_instance.getMMSETo (pkt)

        if hdr_name == "X-Mms-Transaction-ID" :
            return self.mmse_mv_instance.getMMSETransactionID (pkt)

        if hdr_name == "Message-Id" :
            return self.mmse_mv_instance.getMMSEMessageID (pkt)


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

