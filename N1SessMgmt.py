import json
import logging
import pdb

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# Create handlers
f_handler = logging.FileHandler('n1Decoder.log', 'a')
f_handler.setLevel(logging.DEBUG)
# Create formatters and add it to handlers
f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
f_handler.setFormatter(f_format)
# Add handlers to the logger
logger.addHandler(f_handler)

class SMMessage:

    #Here should be objects to store various values

    messageTypValueDict = { 193 : "PDU_SESS_EST_REQ",
                            194 : "PDU_SESS_EST_ACCP",
                            195 : "PDU_SESS_EST_REJ",
                            197 : "PDU_SESS_AUTH_CMD",
                            198 : "PDU_SESS_AUTH_COMPL",
                            199 : "PDU_SESS_AUTH_RES",
                            201 : "PDU_SESS_MOD_REQ",
                            202 : "PDU_SESS_MOD_REJ",
                            203 : "PDU_SESS_MOD_CMD",
                            204 : "PDU_SESS_MOD_COMP",
                            205 : "PDU_SESS_MOD_CMD_REJ",
                            209 : "PDU_SESS_REL_REQ",
                            210 : "PDU_SESS_REL_REJ",
                            211 : "PDU_SESS_REL_CMD",
                            212 : "PDU_SESS_REL_COMP",
                            214 : "5GSM_CAUSE"
                            }

    #IEI, IE, TYP, FORMAT, LEN
    SESS_EST_REQ_LST = ( 
        ('9' , 'PDU_SESS_TYP', 'TV',    '1'),
        ('A' , 'SSC_MODE',     'TV',    '1' ),
        ('28', '5GSM_CASA',    'TLV',   '3-15'),
        ('55', 'MAX_SUPP_FLT', 'TV',    '3'),
        ('B' , 'ALWYS_ON_PDU', 'TV',    '1' ),
        ('39', 'SM_PDU_DN_RQ', 'TLV',   '3-255'),
        ('7B', 'EPCO',         'TLV-E', '4-65538')
    )

    decoded_dict = dict()

    ext_proto_discr = ""
    pdu_sess_id = ""
    msg_typ = ""
    integrity_prot_rate = ""  

    #Methods to decode, print

    def convert_hex_to_int(self, hex_input):
        """
        method with exception handling to convert hex to int
        mostly exception will be caused by ['c', '1'] being
        type casted to int instead of using 'c1'

        On Type Error, try to doa join and then convert
        Log the exception
        """
        return_val = None
        try:
            return_val = int(hex_input, 16)
        except TypeError as typ_err:
            logger.error(typ_err)
            logger.exception("This needs to be fixed. Check stack. Trying again")
            hex_input = "".join(hex_input)
            try:
                return_val = int(hex_input, 16)
            except TypeError as typ_err:
                logger.error(typ_err)
                logger.exception("This needs to be fixed!! did not pass on second try. Check stack. ")

        return return_val



    def decode_sm_header(self, byteVal):
        """ Decode the first 6 bytes 
        ProtoDiscriminator  - 1 byte
        PDU SESS ID - 1 byte
        PTI - 1 byte
        MSG TYP - 1 byte
        Integrity protection - 2 bytes
        """
        #First is the Extended Proto Discriminator
        self.ext_proto_discr        = "".join(byteVal[0:2])
        self.ext_proto_discr_int    = self.convert_hex_to_int(self.ext_proto_discr)
        self.decoded_dict['Extended Prtocol Discriminator'] = self.ext_proto_discr_int

        #PDU Sess ID
        self.pdu_sess_id        = "".join(byteVal[2:4])
        self.pdu_sess_id_int    = self.convert_hex_to_int(self.pdu_sess_id)
        self.decoded_dict['PDU Session ID:'] = self.pdu_sess_id_int
        
        #PTI
        self.pti        = "".join(byteVal[4:6])
        self.pti_int    = self.convert_hex_to_int(self.pti)
        self.decoded_dict['PTI:'] = self.pti_int

        #Message Type
        self.msg_typ        = "".join(byteVal[6:8])
        self.msg_typ_int    = self.convert_hex_to_int(self.msg_typ)
        self.decoded_dict['Message Type:'] = self.getMessageTypeString()

        #Integrity Protection Max data rate
        self.integrity_prot_rate        = "".join(byteVal[8:12])
        self.integrity_prot_rate_int    = self.convert_hex_to_int(self.integrity_prot_rate)
        self.decoded_dict['Integrity Protection Rate:'] = self.integrity_prot_rate


    def store_sm_header(self, ext_discr, pdu_id, mssg_typ, integrity_rate):
        """
        Stores the Hex data the 4 fields in the Header field
        This can be used to build the message later 
        """
        #First is the Extended Proto Discriminator
        self.ext_proto_discr = ext_discr
        #PDU Sess ID
        self.pdu_sess_id = pdu_id
        #Message Type
        self.msg_typ = mssg_typ
        #Integrity Protection Max data rate
        self.integrity_prot_rate = integrity_rate


    def getMessageTypeString(self):
        if self.msg_typ is not None :
            return self.getMessageTypeFromHex(self.msg_typ)


    def getMessageTypeFromHex(self, byteVal):
        """
        Return a string from messageTypValueDict Dict
        Based on the Hex input
        """
        intVal = self.convert_hex_to_int(byteVal)
        return self.messageTypValueDict.get(intVal, "ERROR")


    def decode_pdu_session_type(self, hexVal):
        """
        PDU Sess Typ is only Half a byte and the first half byte is
        the IEI
        After detecting the IEI, this method gets the second half byte
        """
        intVal = self.convert_hex_to_int(hexVal)
        #intVal = int(hexVal, 16)
        if intVal == 1 :
            sessTyp = "IPV4"
        elif intVal == 2 :
            sessTyp = "IPV6" 
        elif intVal == 3 :
            sessTyp = "IPV4V6" 
        elif intVal == 4 :
            sessTyp = "Unstructured" 
        elif intVal == 5 :
            sessTyp = "Ethernet" 
        elif intVal == 6 :
            sessTyp = "reserved"
        else :
            sessTyp = "IPV4V6" 

        self.decoded_dict['PDU Session Type:'] = sessTyp
        print("PDU Session Type: {0}".format(sessTyp))



    def store_pdu_session_type(self, sess_typ_inp):
        """
        Stores the Hex data for the PDU Session Type
        Input is in string and we map it to HEX
        """

        if sess_typ_inp == "IPV4" :
            self.pdu_sess_tpe = 1
        elif sess_typ_inp == "IPV6" :    
            self.pdu_sess_tpe = 2
        elif sess_typ_inp == "IPV4V6" :    
            self.pdu_sess_tpe = 3
        elif sess_typ_inp == "Unstructured" :    
            self.pdu_sess_tpe = 4
        elif sess_typ_inp == "Ethernet" :    
            self.pdu_sess_tpe = 5
        elif sess_typ_inp == "reserved" :    
            self.pdu_sess_tpe = 6
        else :
            self.pdu_sess_tpe = 7




    def decode_ssc_mode(self, hexVal):
        """
        SSC Mode is only Half a byte and the first half byte is
        the IEI
        After detecting the IEI, this method gets the second half byte
        """
        intVal = self.convert_hex_to_int(hexVal)
        if intVal == 1 :
            sscMode = "SSC_MODE_1"
        elif intVal == 2 :
            sscMode = "SSC_MODE_2"
        elif intVal == 3 :
            sscMode = "SSC_MODE_3"
        elif intVal == 4 :
            sscMode = "SSC_MODE_1"
        elif intVal == 5 :
            sscMode = "SSC_MODE_2"
        elif intVal == 6 :
            sscMode = "SSC_MODE_3"
        else :
            sscMode = "UNDEFINED"

        self.decoded_dict['SSC MODE:'] = sscMode
        print("SSC MODE: {0}".format(sscMode))



    def store_ssc_mode(self, ssc_mode_inp):
        """
        Stores the Hex data for SSC MODE
        Input is in string and we map it to HEX
        """

        if ssc_mode_inp == "SSC_MODE_1" :
            self.ssc_mode = 1
        elif ssc_mode_inp == "SSC_MODE_2" :
            self.ssc_mode = 2
        elif ssc_mode_inp == "SSC_MODE_3" :    
            self.ssc_mode = 3
        elif ssc_mode_inp == "SSC_MODE_14" :
            self.ssc_mode = 1
        elif ssc_mode_inp == "SSC_MODE_25" :
            self.ssc_mode = 2
        elif ssc_mode_inp == "SSC_MODE_36" :
            self.ssc_mode = 3
        else :
            print("SSC MODE ERROR. Some Undefined value passed")


    def fivegsm_capability_getlength(self, hexVal):
        """
        HexVal here is the length field of 1 Byte for the 5GSM
        capability IE
        The method returns the number of bytes in the value part
        of this IE
        """
        self.fivegsm_length = self.get_ie_length(hexVal)
        #Check for Length of IE
        if ( self.fivegsm_length < 0 | self.fivegsm_length > 12):
            logger.error(f"validation of 5GSM length failed {self.fivegsm_length}")
        return self.fivegsm_length

    
    def get_ie_length(self, lenBytes):
        # HexVal is one Byte or 2 bytes
        lengthOfIE = "".join(lenBytes)
        lenInInt = self.convert_hex_to_int(lengthOfIE)

        return lenInInt

    def decode_fivegsm_capability(self, hexVal):
        """
        After finding the length of this TLV type 4 IE, pass the
        value part 
        Octate 4 - 15 is Spare so ignore it, decode ony the first octate
        """
        logger.info('Decoding GSM Capability')
        logger.debug(f'Hex: {hexVal}')

        #The first half byte is spare
        #Evaluate the second half
        lsbByte = hexVal[1]

        rqos_mask = "1"
        mhpdu_mask = "2"
        decoded_dict_fivegsm = dict()

        if ( (int(rqos_mask, 16) & int(lsbByte, 16)) == 1 ):
            self.fivegsm_roqs = "1"
            decoded_dict_fivegsm['ROS:'] = 1
            print("5GSM Capability: RQOS SET")
        else:
            self.fivegsm_roqs = "0"
            decoded_dict_fivegsm['ROS:'] = 0
            print("5GSM Capability: Reflective QOS not Supported")
        
        if ( (int(mhpdu_mask, 16) & int(lsbByte, 16)) == 2 ):
            self.fivegsm_mhpdu = "1"
            decoded_dict_fivegsm['MultiHome PDU:'] = 1
            print("5GSM Capability: Multi-homed IPv6 PDU session supported")
        else:
            self.fivegsm_mhpdu = "0"
            decoded_dict_fivegsm['MultiHome PDU:'] = 0
            print("5GSM Capability: Multi-homed IPv6 PDU session not supported")

        self.decoded_dict['5GSM Capabilty'] = decoded_dict_fivegsm


    def store_fivegsm_capability(self, rqos_supp = 0, mhpdu_supp = 0, len_ie = 1):
        """Store the length, and flags to later encode this IE
        """
        self.fivegsm_length = len_ie
        self.fivegsm_mhpdu = mhpdu_supp
        self.fivegsm_roqs = rqos_supp


    def decode_max_supp_filters(self, hexVal):
        """
        This TV type IE has value of 1 byte and 4 bits from the next half byte
        hexVal is the 2 octates of the value field
        OCT1
        OCT2 - here only the 4 bits from the MSB are used rest are spare
        """
        hexbytes_max_len = hexVal[0:2]
        self.maxsuppfilters = hexbytes_max_len

        self.decoded_dict['Maximum Supported Packet Filters'] = self.maxsuppfilters
        print("Maximum Supported Packet Filters: {0}".format(hexbytes_max_len))


    def store_max_supp_filters(self,hexVal=0):
        """
        hexVal is the integer value passed in hex form
        """
        self.maxsuppfilters = hex(hexVal)


    def decode_always_on_pdu(self, hexVal):
        """
        Of form TV. hex val is the half byte represnting the value part
        """
        hexVal = "".join(hexVal)
        apsr_mask = "01"
        if ( int(hexVal, 16) & int(apsr_mask, 16) == 1):
            self.always_on_pdu = 1
            print("Always-on PDU session requested")
        else:
            self.always_on_pdu = 0
            print("Always-on PDU session Not requested")
        
        self.decoded_dict['Always-on PDU session'] = self.always_on_pdu


    def store_always_on_pdu(self, isOn = 0):
        """
        store the always on PDU Session indication for encoding later 
        """
        self.always_on_pdu = isOn

    
    def get_epco_length(self, lenBytes):
        """
        Type 6 TLV_E. Length is 2 bytes.
        """
        epco_length_loc = self.get_ie_length(lenBytes)

        #Check for Length of IE
        if ( epco_length_loc <= 65535 ):
            self.epco_length = epco_length_loc
        else :
            print("Error validating EPCO len")
            self.epco_length = 1

        return self.epco_length


    def decode_epco(self, hexVal):
        """
        It is of type TLV-E
        24.008 10.5.6.3A
        """
        self.epcoHex = "".join(hexVal)
        self.decoded_dict['EPCO'] = self.epcoHex
        print("EPCO: {0}".format(self.epcoHex))


    def print_decoded_mssg(self):
        print(json.dumps(self.decoded_dict, indent=4))
