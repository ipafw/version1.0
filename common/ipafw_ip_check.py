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

class ipafwIPCheck () :

    def __init__ (self, ipafw_self) :
        self.ipafw = ipafw_self

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

    '''
    obj.resetTestContext ()
    print " Reset MSISDN A current dict: ", obj.current_dict ["YAML_VARIABLE_INPUTS"][0]["YAML_MSISDN_A"]
    print " Reset MSISDN A context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_MSISDN_A"]
    print " Reset IMSI A context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_IMSI_A"]
    print " Reset MSISDN B context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_MSISDN_B"]
    print " Reset IMSI B context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_IMSI_B"]
    '''
    pass

