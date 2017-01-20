from cmn_Pass_Fail import Pass_Fail,html_fail,html_pass,FAIL,PASS
from robot.libraries.BuiltIn import BuiltIn
import re
from robot.api import logger
import os
import datetime

PASS = '<b style="color:green">PASS</b>'
FAIL = '<b style="color:red">FAIL</b>'

class SipMessageValidation:
    def getCallID(self, packet):
        return packet.sip.call_ID

    def getCseqSeqNumber(self, packet):
        return packet.sip._all_fields['sip.CSeq.seq']

    def getCseqMethod(self, packet):
        return packet.sip._all_fields['sip.CSeq.method']
    
    def getMessageHeader(self, packet):
        return packet.sip._all_fields['sip.msg_hdr']

    def getFromUser(self, packet):
        try: 
            if hasattr(packet.sip, 'sip.from.user'):
		print "sip.from.user:",packet.sip._all_fields['sip.from.user']
                return packet.sip._all_fields['sip.from.user']
            elif hasattr(packet.sip, 'sip.from.addr'):
		print "sip.from.addr:",packet.sip._all_fields['sip.from.addr']
                return packet.sip._all_fields['sip.from.addr']
            else: 
		print "sip.From:",packet.sip._all_fields['sip.From']
	        return packet.sip._all_fields['sip.From']
        except Exception as e:
            print "Exception in getFromUser: ", str(e)
            return ''

    def getToUser(self, packet):
        try: 
            if hasattr(packet.sip, 'sip.to.user'):
		print "sip.to.user:",packet.sip._all_fields['sip.to.user']
                return packet.sip._all_fields['sip.to.user']
            elif hasattr(packet.sip, 'sip.to.addr'):
		print "sip.to.addr:",packet.sip._all_fields['sip.to.addr']
                return packet.sip._all_fields['sip.to.addr']
            else: 
		print "sip.To:",packet.sip._all_fields['sip.To']
		return packet.sip._all_fields['sip.To']
        except Exception as e:
            print "Exception in getToUser: ", str(e)
            return ''

    def getPAssertedIdentity(self, packet):
        try:
            if hasattr(packet.sip, 'sip.pai.user'):
		print "sip.pai.user:",packet.sip._all_fields['sip.pai.user']
                return packet.sip._all_fields['sip.pai.user']
            elif hasattr(packet.sip, 'sip.pai.addr'):
		print "sip.pai.addr:",packet.sip._all_fields['sip.pai.addr']
                return packet.sip._all_fields['sip.pai.addr']
            else: 
		print "sip.P-Asserted-Identity:",packet.sip._all_fields['sip.P-Asserted-Identity']
		return packet.sip._all_fields['sip.P-Asserted-Identity']
        except Exception as e:
            print "Exception in getPAssertedIdentity: ", str(e)
            return ''

    def getPServedUser(self, packet):
        return packet.sip.P_Served_User

    def validateSipMessage(self, packet, validate_args, prt = []):
	status = True
        for key in validate_args:
            value = validate_args[key]
            all_sip_fields = packet.sip._all_fields

            if key == 'From':
		try:
			from_user = str(self.getFromUser(packet))
			print_value = "\tExpected: From - " + str(value) + "\t\tActual: From - " + from_user
			print "\nprint_value :",print_value
			if str(value) in from_user:
			    print print_value
			    prt.append(print_value+ " - " + PASS)
			else:
			    print "\nprint_value in else:",print_value
			    print print_value
			    prt.append(print_value + " - " + FAIL)
			    status = False
		except Exception as E:
                	print_value = "\tExpected: From - " + str(value) + "\t\tActual: From - " + str(E)
            if key == 'To':
		try:
			to_user = str(self.getToUser(packet))
			print_value = "\tExpected: To - " + str(value) + "\t\tActual: To - " + to_user
			if str(value) in to_user:
			    print print_value
			    prt.append(print_value + " - " + PASS)
			else:
			    print print_value
			    prt.append(print_value + " - " + FAIL)
			    status = False
		except Exception as E:
                	print_value = "\tExpected: To - " + str(value) + "\t\tActual: To - " + str(E)


            if key == 'TO':
                # instead of sip.to.user this method will get the value sip.To
                str_to = str(all_sip_fields['sip.To'])
                sip_to_value = re.search(r'(urn:.*?)[>|;]+.*', str_to).group (1)
                print_value = "\tExpected: To - " + str(value) + "\t\tActual: To - " + sip_to_value
                print print_value
                if str(value) in str(all_sip_fields['sip.To']):
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'FROM':
                # instead of sip.from.user this method will get the value sip.From 
                print_value = "\tExpected: From - " + str(value) + "\t\tActual: From - " + str(all_sip_fields['sip.display.info'])
                print print_value
                if str(value) in str(all_sip_fields['sip.display.info']):
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False
                    

            if key == 'P-Associated-From':
                try:
                    msg = 'P-Associated-From: %s'%(value)
                    print "msg of P-Associated-From in sip message validation",msg
                    if msg in all_sip_fields['sip.msg_hdr']:
                        print ("\tExpected: "+msg+"\t Actual: "+msg)
                        prt.append("\tExpected: "+msg+"\t Actual: "+msg+" - "+PASS)
                    else:
                        print "P-Associated-From Value is Not Matching"
                        prt.append("\tP-Associated-From Value Not Matching" + FAIL)
                        status = False
                except Exception as e:
                    print_value = "\tExpected: P-Associated-From - " + str(value) + "\t\tActual: P-Associated-From - " + str(e)
            
            if key == 'Event':
                print_value = "\tExpected: Event - " + str(value) + "\t\tActual: Event - " + all_sip_fields['sip.Event']
                if all_sip_fields['sip.Event'] == value:
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'P-Asserted-Identity':
		try:
                    pai_user = str(self.getPAssertedIdentity(packet))
                    print_value = "\tExpected: P-Asserted-Identity - " + str(value) + "\t\tActual: P-Asserted-Identity - " + \
                          pai_user

                    if str(value) in pai_user:
                        print print_value
                        prt.append(print_value + " - " + PASS)
                    else:
                        print print_value
                        prt.append(print_value + " - " + FAIL)
                        status = False

		except Exception as e:
                    print_value = "\tExpected: P-Asserted-Identity - " + str(value) + "\t\tActual: P-Asserted-Identity - " + str(e)	
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False		

            if key == 'CSeqMethod':
                print_value = "\tExpected: CSeqMethod - " + str(value) + "\t\tActual: CSeqMethod - " + all_sip_fields[
                    'sip.CSeq.method']
                if value == all_sip_fields['sip.CSeq.method']:
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'Call_ID':
                print_value = "\tExpected: Call_ID - " + str(value) + "\t\tActual: Call_ID - " + all_sip_fields[
                    'sip.Call-ID']
                if value == all_sip_fields['sip.Call-ID']:
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'Expires':
                print_value = "\tExpected: Expires " + str(value) + "\t\tActual: Expires - " + all_sip_fields['sip.Expires']
                if value == '>0':
                    if int(all_sip_fields['sip.Expires']) > 0:
                        print print_value
                        prt.append(print_value + " - " + PASS)
                    else:
                        print print_value
                        prt.append(print_value + " - " + FAIL)
                        status = False

                if value == '=0':
                    if int(all_sip_fields['sip.Expires']) == 0:
                        print print_value
                        prt.append(print_value + " - " + PASS)
                    else:
                        print print_value
                        prt.append(print_value + " - " + FAIL)
                        status = False

            if key == 'userid':
                print_value = "\tExpected : userid " + str(value) + "\t Actual:userid " + all_sip_fields['sip.userid']
                if value in all_sip_fields['sip.userid']:
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'P-Associated-URI':
                print_value = "\tExpected : P-Associated-URI - " + str(value) + "\t\tAcutal: P-Associated-URI - " + \
                              all_sip_fields['sip.P-Associated-URI']

                if value in all_sip_fields['sip.P-Associated-URI']:
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'Subscription-State':
                print_value = "\tExpected : Subscription-State - " + str(value) + "\t\tAcutal: Subscription-State - " + \
                              all_sip_fields['sip.Subscription-State']

                if value in all_sip_fields['sip.Subscription-State']:
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'Subscription-State-Expires':
                msg = all_sip_fields['sip.Subscription-State'].split(';')
                m = msg[1].split('=')
                if value == '>0':
                    if m[1] > 0:
			print ("\tExpected : Subscription-State-Expires "+str(value)+"\t\tAcutal: Subscription-State-Expires - "+m[1])
			prt.append("\tExpected : Subscription-State-Expires "+str(value)+"\t\tAcutal: Subscription-State-Expires - "+m[1]+" - "+PASS)
                    else:
                        print ("\tExpected : Subscription-State-Expires "+str(value)+"\t\tAcutal: Subscription-State-Expires - "+m[1])
                        prt.append("\tExpected : Subscription-State-Expires "+str(value)+"\t\tAcutal: Subscription-State-Expires - "+m[1]+" - "+FAIL)
                        status = False

                if value == '=0':
                    if m[1] == 0:
                        print ("\tExpected : Subscription-State-Expires "+str(value)+"\t\tAcutal: Subscription-State-Expires - "+m[1])
                        prt.append("\tExpected : Subscription-State-Expires "+str(value)+"\t\tAcutal: Subscription-State-Expires - "+m[1]+" - "+PASS)
                    else:
                        print ("\tExpected : Subscription-State-Expires "+str(value)+"\t\tAcutal: Subscription-State-Expires - "+m[1])
                        prt.append("\tExpected : Subscription-State-Expires "+str(value)+"\t\tAcutal: Subscription-State-Expires - "+m[1]+" - "+FAIL)
                        status = False


            if key == 'Content-Type':
                print_value = "\tExpected : Content-Type - " + str(value) + "\t Actual: Content-Type - " + \
                              all_sip_fields['sip.Content-Type']
                if value in all_sip_fields['sip.Content-Type']:
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            # Search for 'P-Prefered association Native/OTT phone nymbers in P-Prefered association string
            if ((key == 'PP_Association_OTT') or (key == 'PP_Association_Native')):
                p_preferred_association_string = re.compile('P-Preferred-Association:(.*?)' + r'\\xd\\xa').search(self.getMessageHeader(packet)).group(1)
                print_value = "\tExpected :" + key + ":" + str(value) + "\t Actual : " + key + " : " + p_preferred_association_string
                if value in p_preferred_association_string:
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False

            # Search for 'cdpn' string in Contact string
            if key == 'P-Preferred-Association':
                msg = 'P-Preferred-Association: sip:%s'%(value)
                if msg in all_sip_fields['sip.msg_hdr']:
                    print "P-Preferred-Association Value is Matching"
                else:
                    print "P-Preferred-Association Value is Not Matching"
                    status = False


            #Search for 'cdpn' string in Contact string 
            if key == 'Contact':
                if value == '=cdpn':
                    if 'cdpn' in packet.sip.Contact:
                        print_value = "\tAs expected 'cdpn' is present in contact string : ", packet.sip.Contact
                        print print_value
                        prt.append(print_value, packet.sip.Contact + " - " + PASS)
                    else:
                        print_value = "\t'cdpn' should not be present in contact string : ", packet.sip.Contact
                        print print_value
                        prt.append(print_value, packet.sip.Contact + " - " + FAIL)
                        status = False

                if value == '!cdpn':
                    if 'cdpn' not in packet.sip.Contact:
                        print_value = "\tAs expected 'cdpn' is present in contact string : ", packet.sip.Contact
                        print print_value
                        prt.append(print_value, packet.sip.Contact + " - " + PASS)
                    else:
                        print_value = "\t'cdpn' should not be present in contact string : ", packet.sip.Contact
                        print print_value
                        prt.append(print_value, packet.sip.Contact + " - " + FAIL)
                        status = False
 
            if key == 'tuple id':
                obj = BuiltIn()
                tuple_count = obj.get_count(all_sip_fields['sip.msg_hdr'], 'tuple id')
                if value == '>0':
                    if ( tuple_count > 0 ):
                        print "\tTuple id found - %s times"%(tuple_count)
                        prt.append('    Tuples Found = %s times'%(tuple_count))
                    else:
                        print "\tTuple id found"
                        prt.append('    Tuples Found')
                        #status = False
	    if key == 'tuplecount':
                obj = BuiltIn()
                tuple_count = obj.get_count(all_sip_fields['sip.msg_hdr'], 'tuple id')
		print "tuple_count: ",tuple_count
                if ( tuple_count ==int(value) ):
                        print "\tTuple count Expected: "+str(value) +"\tTuple count Actual - %s "%(tuple_count)
                        prt.append('\tTuple count Expected: '+str(value) +'\tTuples count Actual = %s '%(tuple_count)+" - " +PASS)
                else:
                        print "\tTuple id found"
                        prt.append('\tTuples Found')

            if key == 'Contact-parameter-expires':
                p = all_sip_fields['sip.Contact'].split('expires=')
                if value == '=0':
                    if int(p[1]) == 0:
                        print ("\tExpected : Contact-Parameter-Expires "+str(value)+"\t\tAcutal: Contact-Parameter-Expires - "+p[1])
                        prt.append("\tExpected : Contact-Parameter-Expires "+str(value)+"\t\tAcutal: Contact-Parameter-Expires - "+p[1]+" - "+PASS)
                    else:
                        print ("\tExpected : Contact-Parameter-Expires "+str(value)+"\t\tAcutal: Contact-Parameter-Expires - "+p[1])
                        prt.append("\tExpected : Contact-Parameter-Expires "+str(value)+"\t\tAcutal: Contact-Parameter-Expires - "+p[1]+" - "+FAIL)
                        status = False

            if key == 'Accept-Contact':
                if value in all_sip_fields['sip.Accept-Contact']:
	            print ("\tExpected: "+key+" - "+value+"\t Actual: "+key+" - "+value)
		    prt.append("\tExpected: "+key+" - "+value+"\t Actual: "+key+" - "+value+" - "+PASS)
		else:
		    print ("\tExpected: "+key+" - "+ value +"\t Actual: "+key+" - "+ all_sip_fields['sip.Accept-Contact'])
		    prt.append("\tExpected: "+key+" - "+ value +"\t Actual: "+key+" - "+ all_sip_fields['sip.Accept-Contact'] +" - "+FAIL)
		    status = False


            if key == 'Multi-P-Associated-To':
                print value
                status = False
                for n,val in value.iteritems():
                    msg = 'P-Associated-To: sip:%s'%(val)
                    if msg in all_sip_fields['sip.msg_hdr']:
                        print "\tP-Associated-To Value is Matching"
                        prt.append('    P-Associated-To: %s'%(msg))
                        status = True
                        break
                    else:
                        continue
                        #print "P-Associated-To Value is Not Matching"
                        #prt.append('    P-Associated-To: %s / Expected: %s'%(msg, value))
                        #status = False
                if status == False:
                    print "\tP-Associated-To Value is Not Matching"

            if key == 'P-Associated-To':
                    msg = 'P-Associated-To: sip:%s'%(value)
                    if msg in all_sip_fields['sip.msg_hdr']:
                        print ("\tExpected: "+msg+"\t Actual: "+msg)
                        prt.append("\tExpected: "+msg+"\t Actual: "+msg+" - "+PASS)
                    else:
                        print "P-Associated-To Value is Not Matching"
                        prt.append("\tP-Associated-To Value Not Matching" + FAIL)
                        status = False

            if key == 'PPAuserid':
                msg = 'userid="%s"'%(value)
                if msg in all_sip_fields['sip.msg_hdr']:
                    print "\tuserid Value Matching"
                else:
                    print "\tuserid Value Not Matching"
                    status = False

	    if key == 'TASIP':
                print_value = "\tExpected: TAS IP address - " + all_sip_fields['sip.from.host'] + "\t\tActual: TAS IP - " + value
                if all_sip_fields['sip.from.host'] in value:
                    prt.append(print_value + " - " + PASS)
                else:
                    prt.append(print_value + " - " + FAIL)
                    status = False

            if key == 'Require':
                print_value = "\tExpected: Require - " + str(value) + "\t\tActual: Require - " + packet.sip._all_fields['sip.Require']
                if value in packet.sip._all_fields['sip.Require']:
                    print print_value
                    prt.append(print_value + " - " + PASS)
                else:
                    print print_value
                    prt.append(print_value + " - " + FAIL)
                    status = False
          
            if key == 'Contribution-ID':
                    msg = 'Contribution-ID: %s'%(value)
                    if msg in all_sip_fields['sip.msg_hdr']:
                        print ("\tExpected: "+msg+"\t Actual: "+msg)
                        prt.append("\tExpected: "+msg+"\t Actual: "+msg+" - "+PASS)
                    else:
                        print "Contribution-ID Value is Not Matching", msg
                        prt.append("\tContribution-ID Value Not Matching " + msg + " " + FAIL)
                        status = False

            if key == 'Conversation-ID':
                    msg = 'Conversation-ID: %s'%(value)
                    if msg in all_sip_fields['sip.msg_hdr']:
                        print ("\tExpected: "+msg+"\t Actual: "+msg)
                        prt.append("\tExpected: "+msg+"\t Actual: "+msg+" - "+PASS)
                    else:
                        print "Conversation-ID Value is Not Matching", msg
                        prt.append("\tConversation-ID Value Not Matching " + msg + " " + FAIL)
                        status = False

        return status

    def updateResults(self, result, message):
        message2 = ''
        if result == True:
            message1 = '<b style="color:green">%s</b> ' % message
            message2 = message1 + " - " + html_pass
        elif result == False:
            message1 = '<b style="color:red">%s</b> ' % message
            message2 = message1 + " - " + html_fail
        elif result == 'MsgBody':
            for i in message:
                message2 = message2 + i + '\n'
	elif result == None:
            message2 = '<b style="color:green">%s</b> ' % message
		
        return message2



    def parseAuthHeader(self,auth_header):
        try:
                n = len("Digest ")
                authheader = auth_header[n:].strip()
                items = auth_header.split(",")
                keyvalues = [i.split("=", 1) for i in items]
                keyvalues = [(k.strip(), v.strip().replace('"', '')) for k, v in keyvalues]
                return  dict(keyvalues)
        except Exceptions as e:
                print ("\tError while parsing Auth Header " + repr(e))
                return ""

    def parseContribution_ID (self, sip_packet) :
        try:
            cont_id_hdr_re = re.compile('Contribution-ID: (.*?)' + r'\\xd\\xa')
            var            = cont_id_hdr_re.search(sip_packet.sip._all_fields['sip.msg_hdr'])
            print "sip_message_validation: parseContribution_ID: val: ", var.group(1)
            return var.group(1)
        except Exception as e:
            print ("\tsip_message_validation: parseContribution_ID: Error while parsing sip packet: " + repr(e))
            return ""

    def parseConversation_ID (self, sip_packet) :
        try:
            conv_id_hdr_re = re.compile('Conversation-ID: (.*?)' + r'\\xd\\xa')
            var            = conv_id_hdr_re.search(sip_packet.sip._all_fields['sip.msg_hdr'])
            if var is None :
                print "sip_message_validation: parseConversation_ID: is empty"
                return ""
            else :
                print "sip_message_validation: parseConversation_ID: val: ", var.group(1)
                return var.group(1)
        except Exception as e:
            print ("\tsip_message_validation: parseConversation_ID: Error while parsing sip packet: " + repr(e))
            return ""

    def parseMessageBody_NS (self, sip_packet) :
        try:
            ns_id_hdr_re = re.compile('NS: (imdn .*?)' + r'\\xd\\xa')
            var            = ns_id_hdr_re.search(sip_packet.sip._all_fields['sip.msg_hdr'])
            print "sip_message_validation: parseMessageBody_NS: val: ", var.group(1)
            return var.group(1)
        except Exception as e:
            print ("\tsip_message_validation: parseMessageBody_NS: Error while parsing sip packet: " + repr(e))
            return ""

    def parseMessageBody_IMDN_ID_Text (self, sip_packet) :
        ''' The IMDN ID is present in message body
            The IMDN ID format is different in Message Text method vs. Message Delivered/Displayed methods
            Example header: imdn.Message-ID: 7fb37951-2-57eb0683-27748\r\n'''
        try:
            imdn_id_hdr_re = re.compile('imdn\.Message-ID: (.*?)' + r'\\xd\\xa')
            var            = imdn_id_hdr_re.search(sip_packet.sip._all_fields['sip.msg_hdr'])
            print "sip_message_validation: parseMessageBody_IMDN_ID_Text: val: ", var.group(1)
            return var.group(1)
        except Exception as e:
            print ("\tsip_message_validation: parseMessageBody_IMDN_ID_Text: Error while parsing sip packet: " + repr(e))
            return ""

    def parseMessageBody_IMDN_ID (self, sip_packet) :
        ''' The IMDN ID is present in Message body
            The IMDN ID format is different in Message Text method vs. Message Delivered/Displayed methods
            Example header: <message-id>7fb37951-2-57eb0683-27748</message-id>\r\n'''
        try:
            imdn_id_hdr_re = re.compile('<message-id>(.*?)</message-id>' + r'\\xd\\xa')
            var            = imdn_id_hdr_re.search(sip_packet.sip._all_fields['sip.msg_hdr'])
            print "sip_message_validation: parseMessageBody_IMDN_ID: val: ", var.group(1)
            return var.group(1)
        except Exception as e:
            print ("\tsip_message_validation: parseMessageBody_IMDN_ID: Error while parsing sip packet: " + repr(e))
            return ""

    def parseMessageBody_CType (self, sip_packet) :
        '''This Content-type is present in the message body
           NOTE: Pay attention to small-case for 'type' Content-type
           This is different from Content-Type in message head. Pay attention to upper-case 'Type' '''
        try:
            ctype_id_hdr_re = re.compile('Content-type: (.*?)' + r'\\xd\\xa')
            var            = ctype_id_hdr_re.search(sip_packet.sip._all_fields['sip.msg_hdr'])
            print "sip_message_validation: parseMessageBody_CType: val: ", var.group(1)
            return var.group(1)
        except Exception as e:
            print ("\tsip_message_validation: parseMessageBody_CType: Error while parsing sip packet: " + repr(e))
            return ""

    def messageDataReassembly (self, capFile, pkt,splitkey) :
        robot_env = BuiltIn()
        robot_env.log_to_console("Before Creating Text FIle")
        print ("Before Creating Text FIle")
        tmp_file = "/tmp/" + datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d_%H-%M-%S') + ".txt"
        robot_env.log_to_console("After Creating Text FIle")
        print ("After Creating Text FIle")
        print "messageDataReassembly: The tmp file is: ", tmp_file

        msg_body = ''

        try:
            cmd1 = "tshark"
            cmd2 = ("-r %s -Y frame.number==%s -Vx > %s"%(capFile, pkt.frame_info.number, tmp_file))
            cmd = cmd1 + " " + cmd2
            print "messageDataReassembly: Tshark Command: ", cmd

            os.system(cmd)

            with open(tmp_file,'r') as fh :
                lines = fh.readlines()

            s_prev1 = s_prev2 = ''
            msg_buf = []
            for line in lines :
                if "0010  " in line [:6] and '0000  ' == s_prev2 [:6] and s_prev1 == '\n':
                   print "messageDataReassembly: Found a new line and first two lines of mesg body"
                   msg_buf.append (s_prev2.rstrip('\n')[56:])
                   msg_buf.append (line.rstrip('\n')[56:])
                elif "0000  " == line [:6] and s_prev1 == '\n':
                   print "messageDataReassembly: Found a new line and first of line of mesg body"
                   s_prev2 = line
                   continue
                elif line == '\n' :
                   print "messageDataReassembly: Found a new line"
                   s_prev1 = line
                   continue
                elif len(msg_buf) > 0 :
                   msg_buf.append (line.rstrip('\n')[56:])
                   continue

            if s_prev1 == '' or s_prev2 == '' :
                print "messageDataReassembly: DID NOT FIND THE MESSAGE BODY IN EXPECTED FORMAT"
                return None

            msg_body = '' . join(msg_buf)
            print "messageDataReassembly: THE Message Body: ", msg_body
            if splitkey:
                print "IF: I am in Splitkey Not None"
                part_body = msg_body.split (splitkey)
                return part_body [1]
            else :
                print "ELSE: I am in Splitkey None"
                return msg_body
        except Exception as E:
            print "messageDataReassembly: Exception occurred in Text parsing ", str(E)
        print ("Out of Try Catch : Printing spilitkey --> "+str(splitkey))

    def messageDataReassembly_xml (self, capFile, pkt, splitkey=None):
        try:           

            os.system("tshark -r %s -Y 'frame.number == %s' -Vx >test.txt"%(capFile, pkt.frame_info.number))
            str1 = open('test.txt','r').read()
            a =str1.split('target')
            b=a[len(a)-1]            
            ls=b.split('\n')
            result = []
            for i in range(len(ls)-2):
                if len(ls[i]) > 16:                    
		    result.append(str(ls[i])[len(ls[i])-16:])
            return str(result).strip('[]').replace(',','').replace("'",'').replace(' ','')
        except Exception as E:
            print "Exception occurred in Text parsing ", str(E)
            
    def getValueforKey(self,body, key, expectedvalue):
        try:
	    if key in body:
                match = re.search(key + '(.+?)>', body)
                result=''
                if expectedvalue == None:
                    result= "\tExpected value: "+str(key) + "\t Actual value: "+str(key) 
		    #result= "\t Value for  "+str(key) + ": "+str(body)
		elif expectedvalue == "":
		    if key in body:
		    	result= "\t Expected value:"+str(key) + "\t Actual value: "+str(match.group(0)) + PASS
		    else:
			result= "\t Expected value:"+str(key) + "\t Actual value: "+str(match.group(0)) + FAIL
                elif expectedvalue in body:
                    result= "\t Expected "+key+": "+str(expectedvalue) + "\tActual Value: "+str(match.group(1)) + PASS
                else:
                    result= "Value "+str(key) +": "+str(expectedvalue) +" not found" + FAIL
                return result
	    else:
		return "Key: "+str(key)+" not found"
        except Exception as e:
            print "Exception in getValueforKey: "+str(e)
    def getValueArrayforKey(self,body, key, expectedvalue):
        try:
            if key in body:
                match = re.search(key + '(.+?)>', body)
                result=[]
                if expectedvalue == None:
                    result.append("\t Value "+str(key) + " is found in the packet")
                    #result= "\t Value for  "+str(key) + ": "+str(body)
                elif expectedvalue == "":
		    res = []
		    p=re.compile(key+'(.+?)>')
		    res = p.findall(body)
		    print "find all result: ",res
		     
                    result= "\t Value(s) for "+str(key) + " : "+ str(res).strip('[]')
                elif expectedvalue in body:
                    result= "\t Expected "+key+": "+str(expectedvalue) + "\tActual Value: "+str(match.group(1)) + PASS
                else:
                    result= "Value "+str(key) +": "+str(expectedvalue) +" not found" + FAIL
                return result
            else:
                return "Key: "+str(key)+" not found"
        except Exception as e:
            print "Exception in getValueforKey: "+str(e)
    
    def checkTupleCount(self,capFile,pkt,count,msg_body):
	try:
	    robot_env= BuiltIn()
	    result = False
	    tupletext = self.messageDataReassembly(capFile,pkt,'')
            tuplecount= robot_env.get_count(tupletext,'<tuple')
            if tuplecount >= count:
		msg_body.append("\tExpected tuple count: "+str(count) +"\tActual tuple count: "+str(tuplecount)+" "+PASS )
		result = True
            else:
                msg_body.append("\tExpected tuple count: "+str(count) +"\tActual tuple count: "+str(tuplecount)+" "+FAIL ) 
   
	    return result
	except Exception as e:
	    print "Exception in checkTupleCount :"+str(e)
