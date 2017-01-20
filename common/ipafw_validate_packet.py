import yaml
import pyshark
import time
import os
import re

import pyshark
from robot.api                             import logger
from robot.libraries.BuiltIn               import BuiltIn

from collections                           import OrderedDict

from cmn_Pass_Fail                         import Pass_Fail,html_fail,html_pass,FAIL,PASS
from parse_global_variables                import parse_TcVariable, ParseGlobalVariable

from ipafw_mmse_proto                      import MMSEMessageValidation
from ipafw_http_proto                      import HTTPMessageValidation
from ipafw_diameter_proto                  import DiameterMessageValidation

class ipafwValidatePacket () :

    def __init__ (self, ipafw_self) :
        self.ipafw = ipafw_self

        self.mmse_mv_instance = MMSEMessageValidation ()
        self.http_mv_instance = HTTPMessageValidation ()
        self.dia_mv_instance  = DiameterMessageValidation ()

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
                result = self.http_mv_instance.validateHTTPMessage (pkt, validate_parameters, self.msg_body)

            if validate_dict ["LAYER"] == "mmse" :
                result = self.mmse_mv_instance.validateMMSEMessage (pkt, validate_parameters, self.msg_body)

            if validate_dict ["LAYER"] == "diameter" :
                result = self.dia_mv_instance.validateDiameterMessage (pkt, validate_parameters, self.msg_body)

            if validate_dict ["LAYER"] == "smpp" :
                result = self.mmse_mv_instance.validateMMSEMessage (pkt, validate_parameters, self.msg_body)

            self.ipafw.result1.append(msg)
            self.ipafw.message.append(self.http_mv_instance.updateResults(result, msg))
            self.ipafw.message.append(self.http_mv_instance.updateResults('MsgBody',self.msg_body))
            self.ipafw.pass_fail_result.append(PASS if result == True else msg)

        print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n"

        print pstr, "VALIDATE PACKET RESULT: ", self.ipafw.result1
        print pstr, "VALIDATE PACKET MESSAGE: ", self.ipafw.message

        if result :
            print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>VALIDATE PACKET CHECK: PASSED, FRAME: ", pkt.frame_info.number, "\n"
            return True
        else :
            print pstr, "\t\t\t\t>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>VALIDATE PACKET CHECK: FAILED, FRAME: ", pkt.frame_info.number
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

