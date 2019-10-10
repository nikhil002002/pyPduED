import N1SessMgmt as IEClass
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


class N1SMDecode:

    #IEI, IE, TYP, FORMAT, LEN
    SESS_EST_REQ_LST = ( 
        ('9' , 'PDU_SESS_TYP', 'TV',    '1',    'pdu_session_type'),
        ('A' , 'SSC_MODE',     'TV',    '1' ,   'ssc_mode'),
        ('28', '5GSM_CASA',    'TLV',   '3-15', 'fivegsm_capability' ),
        ('55', 'MAX_SUPP_FLT', 'TV',    '3',    'max_supp_filters'),
        ('B' , 'ALWYS_ON_PDU', 'TV',    '1',    'always_on_pdu'),
        ('39', 'SM_PDU_DN_RQ', 'TLV',   '3-255', ''),
        ('7B', 'EPCO',         'TLV-E', '4-65538', 'epco')
    )

    MAX_INDEX_HEADER = 12

    def __init__(self):
        self.n1mssg = IEClass.SMMessage()

    def startDecode(self, inpHex):
        """
        Called from the main proc, 
        decodes header and calls Corresponfing decoder
        based on message type
        """
        logger.info("In startDecode")

        hexInpAsLst = list(inpHex)
        inpLen = len(hexInpAsLst)

        if (inpLen < 4 ):
            print("We need atleast 4 bytes")
            logger.info("We need atleast 4 bytes")
            return 0

        #Get the Header decoded
        self.n1mssg.decode_sm_header(hexInpAsLst[:self.MAX_INDEX_HEADER])
        message_type = self.n1mssg.getMessageTypeString()

        if ( message_type == "ERROR" ) :
            print ("unsupported message type")
            return 0
        elif ( message_type == "PDU_SESS_EST_REQ" ) :
            self.decode_pdu_session_establishment(hexInpAsLst[self.MAX_INDEX_HEADER:])
            self.n1mssg.print_decoded_mssg()
        else :
            print("Message decoding not supported yet {0}".format(message_type))




    
    def decode_pdu_session_establishment(self, hexStreamAsLst) :
        """
        Decode PDU Session Estblishment based on IEI 
        hexStreamAsLst is the list of bytes after the header field
        """
        len_of_stream = len(hexStreamAsLst)
        curr_index = 0
        message_type = "PDU_SESS_EST_REQ"

        while curr_index < len_of_stream:

            #pop the first byte to check for a known IEI
            tmp_iei = hexStreamAsLst[curr_index]

            #Check if this IEI matches the first Byte of a known IEI,
            #If not we need to check the secondbyte as well
            returnVal, ie_det_lst = self.match_iei(tmp_iei, message_type)

            if (returnVal):
                #The iei was of a known type
                ret_lst_iei = ie_det_lst[0]
                ret_lst_encodeType = ie_det_lst[2]

                #if IEI length is of a whole byte, we need to consider that
                if (len(ret_lst_iei) == 2):
                    curr_index += 2
                else:
                    curr_index += 1

                #by default assume ie is of type TV
                ie_len = 0

                #check the Type, if Length needs to be evaluated
                if ret_lst_encodeType in ("LV", "TLV", "TLV-E", "LV-E"):
                    # Length needs to be evaluated
                    if ( ie_det_lst[4] == "" ):
                        print("Length Method not defined")
                        return 0
                    try:
                        len_method = getattr(self.n1mssg, (ie_det_lst[4] + "_getlength"))
                    except AttributeError as attr_error:
                        print(attr_error)
                        print("Method name not defined {0}".format(ie_det_lst))
                        logger.exception(f"Method name not defined {ie_det_lst}")
                        return 0
                    else :
                        if ret_lst_encodeType in ("TLV-E", "LV-E"):
                            #these have 2 byte lengths
                            ie_len = len_method( hexStreamAsLst[curr_index:(curr_index + 4)] )
                            curr_index += 4
                        else:
                            #these have 1 byte lengths
                            ie_len = len_method( hexStreamAsLst[curr_index : curr_index + 2] )
                            curr_index += 2

                ### Now that the lngth is known, decode the value part 
                if ( ie_det_lst[4] == "" ):
                    print("Decode Method not defined for {0}".format(ie_det_lst))
                    return 0
                try:
                    len_method = getattr(self.n1mssg, ("decode_" + ie_det_lst[4] ))
                except AttributeError as attr_error:
                    print(attr_error)
                    print("Method name decode_ not defined {0}".format(ie_det_lst))
                else :
                    #pdb.set_trace()
                    len_method( hexStreamAsLst[curr_index:(curr_index + ie_len + 1)] )
                    curr_index = curr_index + ie_len + 1

                #elvaluate next IEI
            else:
                print("Unknown IEI {0}".format(tmp_iei))
                return 0

        #end whilw


    def match_iei(self, ieiHalfByte, typ):
        """
        func that returns true if a match is found based on the first half byte
        return has the list with details
        """
        if (typ == "PDU_SESS_EST_REQ") :
            tupToUse = self.SESS_EST_REQ_LST
        else :
            return False, None

        lst_to_return = None
        found = False

        for currlist in tupToUse:

            #match by the first half
            tmpIei = currlist[0][0]

            if ( int(tmpIei, 16) == int(ieiHalfByte, 16) ):
                #match found 
                #return the tuple
                lst_to_return = currlist
                found = True
                break
        
        return found, lst_to_return
            
