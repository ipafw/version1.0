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

class ipafwStartTestExec () :

    def __init__ (self, ipafw_self) :
        self.ipafw = ipafw_self

        self.mmse_mv_instance = MMSEMessageValidation ()

    def readPcap (self, in_dict, display_filter) :
        pstr = "frameworkTestDriver: readPcap: "

        pcap_location  = in_dict ["VARIABLES"]["YAML_PCAP_LOCATION"]
        pcap_file      = pcap_location + "/" + in_dict ["VARIABLES"]["YAML_PCAP_FILE"]

        in_dict ["PACKET_CAPTURE"] = pyshark.FileCapture(pcap_file, display_filter = display_filter)

    def startYAMLTestValidation (self, current_dict, in_dict) :
        pstr           = "frameworkTestDriver: startYAMLTestValidation: "
        frame_number   = None
        frame_position = None

        for validation in in_dict ["TEST_VALIDATIONS"] :
            print pstr, "order: ", validation ["ORDER"]

            print pstr, "\tconfig data:", validation ["CONFIG"]

            print pstr, "\tpass criteria:", validation ["PASS_CRITERIA"]

            if "VARIABLES" in validation ["CONFIG"] :
                print pstr, "\tconfig variables:", validation ["CONFIG"]["VARIABLES"]
                for setvar in validation ["CONFIG"]["VARIABLES"] :
                    print pstr, "\tconfig variables: ", setvar
                    #self.evalSetVariable (setvar, in_dict)
                    self.ipafw.pty.evalSetVariable (setvar, current_dict)
            else :
                print pstr, "\tconfig variables are not present"

            if "START_FRAME" in validation ["CONFIG"] :
                if "GETVAR" in validation ["CONFIG"]["START_FRAME"] and \
                   "MATCH" in validation ["CONFIG"]["START_FRAME"] :
                    frame_get_var = validation ["CONFIG"]["START_FRAME"]["GETVAR"]
                    frame_number  = in_dict ["VARIABLES"][frame_get_var]
                    frame_position = validation ["CONFIG"]["START_FRAME"]["MATCH"]

            print pstr, "PACKET PARSING TO START FROM: %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%: ", frame_number

            self.startYAMLTestValidationPerFile (validation, in_dict, frame_number, frame_position)

        #self.message.append(self.mmse_mv_instance.updateResults(True,"----------------------------------------------------"))

    def startYAMLTestValidationPerFile (self, validation_per_file, in_dict, frame_number, frame_position) :
        pstr = "frameworkTestDriver: startYAMLTestValidationPerFile: "
        validations = in_dict ["VALIDATIONS"][validation_per_file ["ORDER"]]["VALIDATIONS"]
        print pstr, "ALL VALIDATION IN GIVEN YAML FILE: ", validations

        for current_validation in validations :

            print pstr, "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$VALIDATION PER FILE PER KEY IS: ", current_validation

            print "*****************************************************************\n\n"

            if "IDENTIFY_PACKET" in current_validation :
                self.pkt = self.ipafw.ipkt.identifyPacket (current_validation, in_dict, frame_number, frame_position)
                if self.pkt == None :
                    print pstr, "FAILED TO IDENTIFY PACKET DESCRIBED IN: ", validation_per_file ["CONFIG"]["FILE_NAME"]
                    return

            print "*****************************************************************\n\n"

            if "PARSE_PACKET" in current_validation :
                if self.ipafw.ppkt.parsePacket (current_validation, in_dict, self.pkt) == None:
                    print pstr, "FAILED TO PARSE PACKET DESCRIBED IN: ", validation_per_file ["CONFIG"]["FILE_NAME"]
                    return

            print "*****************************************************************\n\n"

            if "VALIDATE_PACKET" in current_validation :
                if self.ipafw.vpkt.validatePacket (current_validation, in_dict, self.pkt) == None:
                    print pstr, "FAILED TO VALIDATE PACKET DESCRIBED IN: ", validation_per_file ["CONFIG"]["FILE_NAME"]
                    return

            print "*****************************************************************\n\n"

            if "POST_VALIDATION" in current_validation :
                if self.ipafw.postv.postValidation (current_validation, in_dict, self.pkt) == None:
                    print pstr, "FAILED TO PERFORM POST VALIDATION DESCRIBED IN: ", validation_per_file ["CONFIG"]["FILE_NAME"]
                    return

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

