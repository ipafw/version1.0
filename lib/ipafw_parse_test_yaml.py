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

class ipafwParseTestYaml() :

    def __init__ (self, ipafw_self) :
        self.ipafw = ipafw_self

    def readYAML (self, yaml_file) :
        pstr = "frameworkTestDriver: readYAML: "
        with open (yaml_file, "r") as fh:
            try:
                self.yaml_dict = yaml.load (fh)
                #print (self.yaml_dict)
            except yaml.YAMLError as E:
                print (pstr, str(E))
                return None

        #self.current_dict = self.yaml_dict
        return self.yaml_dict

    def printYAMLFileInputs (self, in_dict) :
        pstr = "frameworkTestDriver: printYAMLFileInputs: "
        for yaml_input in in_dict ["YAML_FILE_INPUTS"] :
            print pstr, "file name: ", yaml_input ["FILE_NAME"]

            print pstr, "name space: ", yaml_input ["NAME_SPACE"]

            in_dict [yaml_input ["NAME_SPACE"]] = self.readYAML (yaml_input ["FILE_NAME"])

            print pstr, "YAML FILE INPUTS for: ", yaml_input ["FILE_NAME"], ": ", in_dict [yaml_input ["NAME_SPACE"]]

    def printYAMLVariableInputs (self, in_dict) :
        pstr = "frameworkTestDriver: printYAMLVariableInputs: "

        for yaml_variable in in_dict ["YAML_VARIABLE_INPUTS"] :
            self.evalSetVariable (yaml_variable, in_dict)

        #print "other name: NGN: ", in_dict ["NGN"]
        #print "other name: TC00001: ", in_dict ["TC00001"]

    def evalSetVariable (self, yaml_variable, in_dict) :
        pstr = "frameworkTestDriver: evalSetVariable: "

        print pstr, "variable: ", yaml_variable ["SETVAR"]

        var, keys = yaml_variable ["SETVAR"].split ('=$')
        print pstr, "the var is: ", var

        keys_list = keys.split (':')
        print pstr, "key list first elem: ", keys_list [0]

        prefix = keys_list [0]
        if in_dict [prefix] != None :
            tmp_dict = in_dict
            #for key in keys.split (':') :
            for key in keys_list :
                print pstr, "\tkey is: ", key
                print pstr, "\tdict now is ", tmp_dict [key]
                tmp_dict = tmp_dict [key]

            yaml_variable [var] = str (tmp_dict)

            # Set the evaluated variables directly in context_dict
            self.ipafw.context_dict ["VARIABLES"][var] = str (tmp_dict)
            print pstr, var, ": value is: " , self.ipafw.context_dict ["VARIABLES"][var]
            #print pstr, var, "value is: " , in_dict ["YAML_VARIABLE_INPUTS"][0]
        else :
            print pstr, "format issue"

    def printYAMLTestValidations (self, in_dict) :
        pstr = "frameworkTestDriver: printYAMLTestValidations: "
        for validation in in_dict ["TEST_VALIDATIONS"] :
            print pstr, "order: ", validation ["ORDER"]

            print pstr, "\tconfig data:", validation ["CONFIG"]

            print pstr, "\tpass criteria:", validation ["PASS_CRITERIA"]


    def parseYAMLTestValidation (self, in_dict) :
        pstr = "frameworkTestDriver: parseYAMLTestValidations: "
        for validation in in_dict ["TEST_VALIDATIONS"] :
            print pstr, "order: ", validation ["ORDER"]

            print pstr, "\tconfig data:", validation ["CONFIG"]

            self.ipafw.context_dict ["VALIDATIONS"][validation ["ORDER"]] = self.readYAML (validation ["CONFIG"]["FILE_NAME"])

            #if "SETVAR" in validation ["CONFIG"] :
            #    self.evalSetVariable (validation ["CONFIG"], in_dict)
            print pstr, "\tpass criteria:", validation ["PASS_CRITERIA"]

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

