import yaml
import pyshark
import time
import os
import re

import pyshark

from collections                           import OrderedDict

from sip_message_validation                import SipMessageValidation
from http_message_validation               import HTTPMessageValidation
from cmn_Pass_Fail                         import Pass_Fail,html_fail,html_pass,FAIL,PASS
from parse_global_variables                import parse_TcVariable, ParseGlobalVariable

from ipafw_mmse_proto                      import MMSEMessageValidation
from ipafw_http_proto                      import HTTPMessageValidation
from ipafw_diameter_proto                  import DiameterMessageValidation

from ipafw_parse_test_yaml                 import ipafwParseTestYaml
from ipafw_start_test_exec                 import ipafwStartTestExec
from ipafw_identify_packet                 import ipafwIdentifyPacket
from ipafw_parse_packet                    import ipafwParsePacket
from ipafw_validate_packet                 import ipafwValidatePacket
from ipafw_post_validate                   import ipafwPostValidation

from ipafw_ip_check                        import ipafwIPCheck
from ipafw_protocol_check                  import ipafwProtocolCheck

from ipafw_frame_wrapper                   import ipafwFrame
from ipafw_http_wrapper                    import ipafwHTTP
from ipafw_mmse_wrapper                    import ipafwMMSE
from ipafw_diameter_wrapper                import ipafwDiameter

class frameworkTestDriver () :

    def __init__ (self, yaml_file):
        self.current_dict = {}
        self.context_dict = {}
        self.yaml_file    = yaml_file

        self.pty   = ipafwParseTestYaml (self)
        self.ste   = ipafwStartTestExec (self)
        self.ipkt  = ipafwIdentifyPacket (self)
        self.ppkt  = ipafwParsePacket (self)
        self.vpkt  = ipafwValidatePacket (self)
        self.postv = ipafwPostValidation (self)

        self.ipchk = ipafwIPCheck (self)
        self.pchk  = ipafwProtocolCheck (self)

        self.frame = ipafwFrame (self)
        self.http  = ipafwHTTP (self)
        self.mmse  = ipafwMMSE (self)
        self.dia   = ipafwDiameter (self)

        self.setTestContext ()

    def setTestContext (self) :

        self.context_dict ["VARIABLES"]   = {}
        self.context_dict ["VALIDATIONS"] = {}
        self.result1                      = []
        self.message                      = []
        self.pass_fail_result             = []

        self.current_dict = self.pty.readYAML (self.yaml_file)
        #print "yaml dict: ", self.current_dict

        self.pty.printYAMLFileInputs (self.current_dict)
        self.pty.printYAMLVariableInputs (self.current_dict)
        self.pty.printYAMLTestValidations (self.current_dict)

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


if __name__ == '__main__':
    #obj = frameworkTestDriver ()
    obj = frameworkTestDriver ("drt_mmsc_misc_00030.yaml")

    print " MSISDN A current dict: ", obj.current_dict ["YAML_VARIABLE_INPUTS"][0]["YAML_MSISDN_A"]
    print " MSISDN A context dict: ", obj.context_dict ["VARIABLES"]["YAML_MSISDN_A"]

    print "The context dict is: ", obj.context_dict

    print " IMSI A current dict: ", obj.current_dict ["YAML_VARIABLE_INPUTS"][1]["YAML_IMSI_A"]
    print " IMSI A context dict: ", obj.context_dict ["VARIABLES"]["YAML_IMSI_A"]

    print " MSISDN B context dict: ", obj.context_dict ["VARIABLES"]["YAML_MSISDN_B"]

    print " IMSI B context dict: ", obj.context_dict ["VARIABLES"]["YAML_IMSI_B"]

    obj.pty.parseYAMLTestValidation (obj.current_dict)

    print "VALIDATIONS DICT: ", obj.context_dict ["VALIDATIONS"]
    
    # Note these variables will bear only the last test validation that had set them
    # Each test validation may overwrite variables set in TEST_VALIATIONS section
    #print " YAML_IP_DST context dict: ", obj.context_dict ["VARIABLES"]["YAML_IP_DST"]
    #print " YAML_IP_SRC context dict: ", obj.context_dict ["VARIABLES"]["YAML_IP_SRC"]

    print " PCAP FILE NAME: ", obj.context_dict ["VARIABLES"]["YAML_PCAP_FILE"]
    print " PCAP LOCATION: ", obj.context_dict ["VARIABLES"]["YAML_PCAP_LOCATION"]
    print " PCAP DISPLAY FILTER: ", obj.context_dict ["READ_PCAP"]["OPEN_PCAP_WITH_FILTER"]

    obj.display_filter = obj.context_dict ["READ_PCAP"]["OPEN_PCAP_WITH_FILTER"]
    obj.ste.readPcap (obj.context_dict, obj.display_filter)

    #obj.startYAMLTestValidation (obj.context_dict ["VALIDATIONS"])
    obj.ste.startYAMLTestValidation (obj.current_dict, obj.context_dict)

    '''
    obj.resetTestContext ()
    print " Reset MSISDN A current dict: ", obj.current_dict ["YAML_VARIABLE_INPUTS"][0]["YAML_MSISDN_A"]
    print " Reset MSISDN A context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_MSISDN_A"]
    print " Reset IMSI A context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_IMSI_A"]
    print " Reset MSISDN B context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_MSISDN_B"]
    print " Reset IMSI B context dict: ", obj.context_dict ["YAML_VARIABLE_INPUTS"]["YAML_IMSI_B"]
    '''

