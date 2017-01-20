from robot.api                             import logger
from robot.libraries.BuiltIn               import BuiltIn
from cmn_Pass_Fail                         import Pass_Fail, html_fail, html_pass, FAIL, PASS

from ipafw                                 import frameworkTestDriver

class drt_mmsc_misc_00030 ():

    def setup (self) :
        pass

    def perfectoSteps (self) :
        pass

    def pcapParsingSteps (self) :
        self.ftd = frameworkTestDriver ("drt_mmsc_misc_00030.yaml")

        print " MSISDN A current dict: ", self.ftd.current_dict ["YAML_VARIABLE_INPUTS"][0]["YAML_MSISDN_A"]
        print " MSISDN A context dict: ", self.ftd.context_dict ["VARIABLES"]["YAML_MSISDN_A"]

        print "The context dict is: ", self.ftd.context_dict

        print " IMSI A current dict: ", self.ftd.current_dict ["YAML_VARIABLE_INPUTS"][1]["YAML_IMSI_A"]
        print " IMSI A context dict: ", self.ftd.context_dict ["VARIABLES"]["YAML_IMSI_A"]

        print " MSISDN B context dict: ", self.ftd.context_dict ["VARIABLES"]["YAML_MSISDN_B"]

        print " IMSI B context dict: ", self.ftd.context_dict ["VARIABLES"]["YAML_IMSI_B"]

        self.ftd.pty.parseYAMLTestValidation (self.ftd.current_dict)

        print "VALIDATIONS DICT: ", self.ftd.context_dict ["VALIDATIONS"]

        print " PCAP FILE NAME: ", self.ftd.context_dict ["VARIABLES"]["YAML_PCAP_FILE"]
        print " PCAP LOCATION: ", self.ftd.context_dict ["VARIABLES"]["YAML_PCAP_LOCATION"]
        print " PCAP DISPLAY FILTER: ", self.ftd.context_dict ["READ_PCAP"]["OPEN_PCAP_WITH_FILTER"]

        self.ftd.display_filter = self.ftd.context_dict ["READ_PCAP"]["OPEN_PCAP_WITH_FILTER"]
        self.ftd.ste.readPcap (self.ftd.context_dict, self.ftd.display_filter)

        self.ftd.ste.startYAMLTestValidation (self.ftd.current_dict, self.ftd.context_dict)

    def displayResults(self):
        for msg in self.ftd.message:
            logger.info (msg, html=True)

        self.ftd.pf = Pass_Fail ()
        self.ftd.pf.pass_fail (self.ftd.pass_fail_result)

