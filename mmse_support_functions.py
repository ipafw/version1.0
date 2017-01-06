import re
import os

class MMSESupportFunctions () :

    def __init__ (self) :
        self.mmse_methods  = {
                              "128" : "m-send-req",
                              "129" : "m-send-conf",
                              "130" : "m-notification-ind",
                              "131" : "m-notifyresp-ind",
                              "132" : "m-retrieve-conf",
                              "134" : "m-delivery-ind",
                              "135" : "m-read-rec-ind"
                             }

    def getMMSEMethodID (self, method_name) :
        pstr = "MMSESupportFunctions: getMMSEMethodID: "

        # Find the method key/id from the method name
        for dict_method_id, dict_method_name in self.mmse_methods.items() :
            if dict_method_name == method_name :
                print pstr, "Method name: ", method_name, " - match found"
                print pstr, "Method ID is: ", dict_method_id
                return dict_method_id

        print pstr, "Method name: ", method_name, " - match not found"
        return None

 
