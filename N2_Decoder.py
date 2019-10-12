import sys, getopt
import re
import pdb as debugger
import logging
import NGAP_DEC
from pycrate_asn1dir import RRC3G
from pycrate_asn1rt import utils

#00000400820008081e8480203d09000086000100008b001a09f0114610103ffe0000000000000000000011461010400101050088000700050000052000

from binascii import unhexlify
from binascii import hexlify


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# Create handlers
f_handler = logging.FileHandler('n2EncoderDecoder.log', 'a')
f_handler.setLevel(logging.DEBUG)
# Create formatters and add it to handlers
f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
f_handler.setFormatter(f_format)
# Add handlers to the logger
logger.addHandler(f_handler)


def test():
    t = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupRequestTransfer
    print(t)
    #help(t)
    #t.from_aper(unhexlify('00000400820008081e8480203d09000086000100008b001a09f0114610103ffe0000000000000000000011461010400101050088000700050000052000'))
    t.from_aper(unhexlify('00000400820008081e8480203d09000086000100008b001a09f0114610103ffe0000000000000000000011461010400101050088000700050000052000'))

    #t()

    print(t.to_asn1())

    print()
    print(t())
    print()
    print()
    #print(t.get_internals())
    print()
    print()
    print(t.get_root())
    print()
    print()
    print(t.get_root_path())
    print()
    print()
    print(t.get_val())
    print()
    print()
    print(t.get_val_paths())
    print()
    print()
    tmp = t.get_val()
    print(tmp['protocolIEs'])
    for obj in tmp['protocolIEs']:
        print()
        print(obj)
        print()
        print()
        print()

    print()
    print()
    print()
    print (tmp['protocolIEs'][0]['value'][1]['pDUSessionAggregateMaximumBitRateDL'])

    #t.set_val_at(tmp['protocolIEs'][0]['value'][1]['pDUSessionAggregateMaximumBitRateDL'], 6000000 )
    #t.set_val_at(['protocolIEs', 0, 'value', 1, 'pDUSessionAggregateMaximumBitRateDL'], 6000000 )

    t.set_val_at(['protocolIEs', 0, 'value', 'PDUSessionAggregateMaximumBitRate', 'pDUSessionAggregateMaximumBitRateDL'], 6000000)
    print(t.to_asn1())
#
#    ##from pycrate_asn1c import asnproc
#    ## asnproc.generate_all()


def testPcch():

    pcch = RRC3G.Class_definitions.PCCH_Message
    pcch.from_uper(unhexlify('4455c803999055c601b95855aa06b09e'))
    print(pcch())
    print(pcch.to_asn1())

    v = pcch()
    print(v)
    print()
    print()
    print(v['message'][1]['pagingRecordList'][0][1])
    print()
    print()
    print(v['message'][1]['pagingRecordList'][0])   
    print()
    print()
    print(pcch.get_proto())
    print()
    print()
    print(utils.get_obj_at(pcch, ['message', 'pagingType1', 'pagingRecordList', None, 'utran-Identity']))
    print()
    print()
    print(utils.get_val_at(pcch, ['message', 'pagingType1', 'pagingRecordList', 2]))

    print("#######################")
    pcch2 = RRC3G.Class_definitions.PCCH_Message
    print()
    print()
    print(utils.get_obj_at(pcch2, ['message', 'pagingType1', 'pagingRecordList', None, 'utran-Identity']))
    print()
    print()
    #this dsnt work when we have never decoded anything
    print(utils.get_val_at(pcch2, ['message', 'pagingType1', 'pagingRecordList', 2]))


def encode_PduSessionResourceSetupRequestTransfer_2(**kwargs):
    """
    Pass values to encode and return a hex stream
    """

    name   = kwargs['name'] if 'name' in kwargs else None

    #if 'name'      in kwargs: self._name    = kwargs['name']
    #if 'mode'      in kwargs: self._mode    = kwargs['mode']

    #elif 'default' in kwargs: self._def     = kwargs['default']
    #if 'defby'     in kwargs: self._defby   = kwargs['defby']
    #if 'uniq'      in kwargs: self._uniq    = kwargs['uniq']
    #if 'group'     in kwargs: self._group   = kwargs['group']
    
    
    encodeObj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupRequestTransfer
    t = encodeObj.get_proto()
    #en = encodeObj()
    print(t)
    print()
    print()
    #print(encodeObj.get_root()) #<PDUSessionResourceSetupRequestTransfer (SEQUENCE)>
    #print(encodeObj._root)   #['protocolIEs']
    #print(encodeObj._root_mand) #['protocolIEs']
    #print(encodeObj._root_opt) #[]
    #print(dir(encodeObj))
    """
['CLASS', 'DEFAULT_TRANS', 'ENV_SEL_TRANS', 'TAG', 'TYPE', '_ASN1Obj__to_ber_codec_set', 
'_ASN1Obj__to_ber_codec_unset', '_SAFE_BND', '_SAFE_BNDTAB', '_SAFE_DYN', '_SAFE_INIT', '_SAFE_STAT', '_SAFE_VAL', '_SILENT',
'__bin__', '__bytes__', '__call__', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', 
'__getattribute__', '__gt__', '__hash__', '__hex__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', 
'__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 
'_chk_hier', '_chk_trans', '_const_tab', '_const_val', '_cont', '_cont_tags', '_decode_ber_cont', '_decode_ber_cont_ws', '_def', 
'_encode_ber_cont', '_encode_ber_cont_ws', '_env', '_ext', '_ext_group', '_ext_group_obj', '_ext_ident', '_ext_nest', 
'_from_asn1', '_from_ber', '_from_ber_ws', '_from_jval', '_from_jval_wrap', '_from_per', '_from_per_ws', '_get_obj_by_path', 
'_get_proto_old', '_get_tab_obj', '_get_tab_obj_nonuniq', '_get_tab_obj_uniq', '_get_val_by_path', '_group', '_hier', 
'_log', '_mod', '_mode', '_name', '_opt', '_param', '_parent', '_root', '_root_mand', '_root_opt', '_safechk_bnd',
'_safechk_obj', '_safechk_set', '_safechk_set_int', '_safechk_set_real', '_safechk_set_str', '_safechk_val', '_safechk_val_int', 
'_safechk_val_real', '_safechk_val_str', '_safechk_valcompl', '_tag', '_tagc', '_to_asn1', '_to_ber', '_to_ber_ws', '_to_jval', 
'_to_jval_wrap', '_to_per', '_to_per_ws', '_tr', '_trans', '_transauto', '_typeref', '_uniq', '_val', 'bin', 'dec_hier', 
'from_aper', 'from_aper_ws', 'from_asn1', 'from_ber', 'from_ber_ws', 'from_bytes', 'from_cer', 'from_cer_ws', 'from_der', 
'from_der_ws', 'from_gser', 'from_int', 'from_jer', 'from_json', 'from_uint', 'from_uper', 'from_uper_ws', 'fullname', 
'get_at', 'get_complexity', 'get_const', 'get_env', 'get_header', 'get_hier', 'get_hier_abs', 'get_internals', 'get_len', 
'get_next', 'get_payload', 'get_prev', 'get_proto', 'get_root', 'get_root_path', 'get_trans', 'get_type_list', 
'get_typeref', 'get_typeref_list', 'get_val', 'get_val_at', 'get_val_paths', 'hex', 'in_class', 'inc_hier', 'iter_cont', 
'reautomate', 'set_env', 'set_hier', 'set_trans', 'set_transauto', 'set_val', 'set_val_at', 'set_val_unsafe', 'show', 
'to_aper', 'to_aper_ws', 'to_asn1', 'to_ber', 'to_ber_ws', 'to_bytes', 'to_cer', 'to_cer_ws', 'to_der', 'to_der_ws', 
'to_gser', 'to_int', 'to_jer', 'to_json', 'to_uint', 'to_uper', 'to_uper_ws']
    """

    #print(t[1])
    #for obj in t[1]['protocolIEs'][1]:
    #    print()
    #    print()
    #    #print(obj)

    #t2 = utils.get_obj_at(encodeObj, '')    #<PDUSessionResourceSetupRequestTransfer (SEQUENCE)>
    #print(t2)

    #Works if it something is already decoded
    #encodeObj.set_val_at(['protocolIEs', 0, 'value', 'PDUSessionAggregateMaximumBitRate', 'pDUSessionAggregateMaximumBitRateDL'], 6000000)
    #encodeObj.set_val_at(['protocolIEs', 0, 'value', 'PDUSessionAggregateMaximumBitRate', 'pDUSessionAggregateMaximumBitRateUL'], 5000000)
    print()
    print()
    print()

    #It is a None type if nothing has been decoded before and we are only encoding
    print(encodeObj.to_asn1())

    print(utils.get_obj_at(encodeObj, ['protocolIEs']))
    #<protocolIEs ([ProtocolIE-Container] SEQUENCE OF)>

    print(utils.get_obj_at(encodeObj, ['protocolIEs', 'value']))
    #<_item_ ([ProtocolIE-Field] SEQUENCE)>

    #After this no key works as the dict only holds
    #{'id': <id ([NGAP-PROTOCOL-IES.&id] INTEGER)>, 'criticality': <criticality ([NGAP-PROTOCOL-IES.&criticality] ENUMERATED)>, 'value': <value ([NGAP-PROTOCOL-IES.&Value] OPEN_TYPE)>}
    #so the below statement will error out
    #print(utils.get_obj_at(encodeObj, ['protocolIEs', 'value', 0]))

    # We need to build protocolIEs

    newEncodeObj = NGAP_DEC.NGAP_PDU_Descriptions.NGAP_PDU
    print("1")
    print("")
    print(newEncodeObj)
    print("")
    #print(newEncodeObj.get_proto())
    #<NGAP-PDU (CHOICE)>

    new2EncodeObj = NGAP_DEC.NGAP_PDU_Contents.PDUSessionResourceSetupRequest
    print("2")
    print("")
    print(new2EncodeObj)
    #print(new2EncodeObj.get_proto())
    #pDUSessionResourceSetup ([NGAP-ELEMENTARY-PROCEDURE] CLASS): {'InitiatingMessage': <InitiatingMessage ([PDUSessionResourceSetupRequest] SEQUENCE)>, 'SuccessfulOutcome': <SuccessfulOutcome ([PDUSessionResourceSetupResponse] SEQUENCE)>, 'procedureCode': 29, 'criticality': 'reject'}>

    new3EncodeObj = NGAP_DEC.NGAP_PDU_Contents.PDUSessionResourceSetupRequestIEs
    print("3")
    print("")
    #print(new3EncodeObj)
    #print(new3EncodeObj.get_proto())
    #<PDUSessionResourceSetupRequest (SEQUENCE)>
    #PDUSessionResourceSetupRequestIEs is the RAm to AMF message and it contains the PDUSessionResourceSetupRequestTransferIEs whihc we want


    new4EncodeObj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupRequestTransferIEs
    print("4")
    print("")
    print(new4EncodeObj)
    #An ASN.1 set is a specific object within the pycrate ASN.1 runtime. It has a root part and an extended part. Moreover, it is callable with some built-in filtering features.
    #<PDUSessionResourceSetupRequestIEs ([NGAP-PROTOCOL-IES] CLASS): ASN1Set(root=[{'id': 10, 'criticality': 'reject', 'Value': <Value ([AMF-UE-NGAP-ID] INTEGER)>, 'presence': 'mandatory'}, {'id': 85, 'criticality': 'reject', 'Value': <Value ([RAN-UE-NGAP-ID] INTEGER)>, 'presence': 'mandatory'}, {'id': 83, 'criticality': 'ignore', 'Value': <Value ([RANPagingPriority] INTEGER)>, 'presence': 'optional'}, {'id': 38, 'criticality': 'reject', 'Value': <Value ([NAS-PDU] OCTET STRING)>, 'presence': 'optional'}, {'id': 74, 'criticality': 'reject', 'Value': <Value ([PDUSessionResourceSetupListSUReq] SEQUENCE OF)>, 'presence': 'mandatory'}], ext=[])>

    print(new4EncodeObj._cont)
    '''
{
id: <id ([ProtocolIE-ID] INTEGER):  >,
criticality: <criticality ([Criticality] ENUMERATED):  >,
Value: <Value (OPEN_TYPE)>,
presence: <presence ([Presence] ENUMERATED):  >
}
    '''


    for ie in NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupRequestTransferIEs().root: print(ie)
    '''
{'id': 130, 'criticality': 'reject', 'Value': <Value ([PDUSessionAggregateMaximumBitRate] SEQUENCE)>, 'presence': 'optional'}
{'id': 139, 'criticality': 'reject', 'Value': <Value ([UPTransportLayerInformation] CHOICE)>, 'presence': 'mandatory'}
{'id': 126, 'criticality': 'reject', 'Value': <Value ([UPTransportLayerInformation] CHOICE)>, 'presence': 'optional'}
{'id': 127, 'criticality': 'reject', 'Value': <Value ([DataForwardingNotPossible] ENUMERATED)>, 'presence': 'optional'}
{'id': 134, 'criticality': 'reject', 'Value': <Value ([PDUSessionType] ENUMERATED)>, 'presence': 'mandatory'}
{'id': 138, 'criticality': 'reject', 'Value': <Value ([SecurityIndication] SEQUENCE)>, 'presence': 'optional'}
{'id': 129, 'criticality': 'reject', 'Value': <Value ([NetworkInstance] INTEGER)>, 'presence': 'optional'}
{'id': 136, 'criticality': 'reject', 'Value': <Value ([QosFlowSetupRequestList] SEQUENCE OF)>, 'presence': 'mandatory'}
'''

    IEs = [] # let's build the list of IEs values
    IEs.append({'id': 130, 'criticality': 'reject', 'value': ('PDUSessionAggregateMaximumBitRate', {'pDUSessionAggregateMaximumBitRateDL': 6000000, 'pDUSessionAggregateMaximumBitRateUL': 4000000 })})
    IEs.append({'id': 134, 'criticality': 'reject', 'value': ('PDUSessionType', 'ipv4')})
    IEs.append({'id': 139, 'criticality': 'reject', 'value': ('UPTransportLayerInformation', ('gTPTunnel', {'transportLayerAddress': (98615294594055401567350253808623404875904323600, 160), 'gTP-TEID': b'@\x01\x01\x05'}))})
    IEs.append({'id': 136, 'criticality': 'reject', 'value': ('QosFlowSetupRequestList', [{'qosFlowIdentifier': 5, 'qosFlowLevelQosParameters': { 'qosCharacteristics': ('nonDynamic5QI', {'fiveQI': 5}), 'allocationAndRetentionPriority': { 'priorityLevelARP': 9, 'pre-emptionCapability': 'shall-not-trigger-pre-emption', 'pre-emptionVulnerability': 'not-pre-emptable' } } }]) })
    val = { 'protocolIEs': IEs }
    myObj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupRequestTransfer
    myObj.set_val(val)
    print(myObj.to_asn1())

    print(hexlify(myObj.to_aper()))

    #IEs.append({'id': 34 , 'criticality': 'ignore', 'value': ('LAI', {'pLMNidentity': b'\x00\x01\xf1', 'lAC': b'\x00\x01'})})
    #IEs.append({'id': 55, 'criticality': 'ignore', 'value': ('RAC', b'\x10')})
    #Es.append({'id': 58, 'criticality': 'ignore', 'value': ('SAI', {'sAC': b'\xff\xff', 'pLMNidentity': b'\x00\x01\xf1', 'lAC': b'\x00\x01'})})
    ##val = ('initiatingMessage', {'procedureCode': 20, 'value': ('DirectTransfer', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    ##PDU.set_val(val)
    ##print(PDU.to_asn1())

class N2Decoder2:

    def start_decode(self, **kwargs):
        """
        Decoder works based on a Hex string passed from the cmd Line

        Usage: N2_Encode_Decode.py encode -x[--hex] <hexstring>

        Supported message types:
            PDU_SESS_RSRC_SETUP_REQ
            PDU_SESS_RSRC_SETUP_RSP
            PDU_SESS_RSRC_MOD_REQ
            PDU_SESS_RSRC_MOD_RSP
            PDU_SESS_RSRC_NOTF
            PDU_SESS_RSRC_MOD_IND
            PDU_SESS_RSRC_MOD_CONF
        """
        if 'msg_type' in kwargs and 'hex' in kwargs:
            msg_to_decode = kwargs['msg_type']
            hex_ip = kwargs['hex']
        else:
            logger.error("The Config file did not have a key for msg_type and a hex value. You need to pass the hex and type of message you want to decode")
            return 

        #########################
        logger.info(f"Starting Decode of {hex_ip} Message To Decode {msg_to_decode}")
        #########################

        if msg_to_decode == 'PDU_SESS_RSRC_SETUP_REQ':
            ret = self.decode_PduSessionResourceSetupRequestTransfer(hex_ip)

        elif msg_to_decode == 'PDU_SESS_RSRC_SETUP_RSP':
            ret = self.decode_PduSessionResourceSetupResponseTransfer(hex_ip)

        elif msg_to_decode == 'PDU_SESS_RSRC_MOD_REQ':
           ret = self.decode_PduSessionResourceModifyRequestTransfer(hex_ip) 

        elif msg_to_decode == 'PDU_SESS_RSRC_MOD_RSP':
           ret = self.decode_PduSessionResourceModifyResponseTransfer(hex_ip) 
            
        elif msg_to_decode == 'PDU_SESS_RSRC_NOTF':
           ret = self.decode_PduSessionResourceNotifyTransfer(hex_ip) 
            
        elif msg_to_decode == 'PDU_SESS_RSRC_MOD_IND':
           ret = self.decode_PduSessionResourceModifyIndicationTransfer(hex_ip)
            
        elif msg_to_decode == 'PDU_SESS_RSRC_MOD_CONF':
           ret = self.decode_PduSessionResourceModifyConfirmTransfer(hex_ip)
            
        else:
            logger.error(f"msg_type {msg_to_decode} is undefined")
            return 0

        print(f"Decoded Value is: {ret}")





    def decode_PduSessionResourceSetupRequestTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Setup Response Transfer
        """
        debug       = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupRequestTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Setup Transfer Req. Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret


    def decode_PduSessionResourceSetupResponseTransfer(self, hexString, **kwargs):

        debug       = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupResponseTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Response Transfer Req. Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret




    def decode_PduSessionResourceModifyRequestTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Setup Resource Modify Request Transfer
        """
        debug       = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj =NGAP_DEC.NGAP_IEs.PDUSessionResourceModifyRequestTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Modify Req transfer. Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PduSessionResourceModifyResponseTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Setup Resource Modify Response Transfer
        """
        debug       = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceModifyResponseTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Modify Resp Transfer. Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PduSessionResourceNotifyTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Setup Resource Notify Transfer
        """
        debug       = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceNotifyTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Rsrc Notify Transfer. Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PduSessionResourceModifyIndicationTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Resource Modify Indication Transfer
        """
        debug       = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceModifyIndicationTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Rsrc Modify Indication Transfer. Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret




    def decode_PduSessionResourceModifyConfirmTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Resource Modify Confirm Transfer
        """
        debug       = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceModifyConfirmTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Rsrc Modify Confirm Transfer. Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret






class N2Decoder:

    def start_encode(self, **kwargs):
        """
        Encoder works based on arguments passed from the passed config files
        In the form of a json string with key value pairs

        Usage: N2_Encode_Decode.py encode -i sample_config.json

        Sample:
        {
            "msg_type" : "PDU_SESS_RSRC_SETUP_REQ",
            "ambr" : {
                "1": 6000000,
                "2": 6000000
                },
            "pdu_typ" : "ipv4", 
            "qfi" : [ { "1": "5", "2": "5", "3": "9", "4":"shall-not-trigger-pre-emption", "5":"not-pre-emptable"} ],
            "gtp_tunn" : {"1":"98615294594055401567350253808623404875904323600", "2": "40010105"}
        }

        for what keys can be used as arguments for encoding a particular message check out the detailed help command
        To use the detailed help command, in the config file, set msg_typ to one of the below supported types
        and give a second key "help" : "true"
        
        Supported message types:
        PDU_SESS_RSRC_SETUP_REQ
        PDU_SESS_RSRC_SETUP_RSP

        """
        help_flag = 0

        #Check if msg type is present
        if 'msg_type' in kwargs:
            msg_to_encode = kwargs['msg_type']
            del kwargs['msg_type']
        else:
            logger.error("The Config file did not have a key for msg_typ. You need to pass the type of message you want to encode")
            return 0

        if 'help' in kwargs:
            help_flag = 1

        if msg_to_encode == 'PDU_SESS_RSRC_SETUP_REQ':
            if help_flag != 1 :
                ret = self.encode_PduSessionResourceSetupRequestTransfer(**kwargs)
            else:
                print(self.encode_PduSessionResourceSetupRequestTransfer.__doc__)
                return 0

        elif msg_to_encode == 'PDU_SESS_RSRC_SETUP_RSP':
            if help_flag != 1 :
                ret = self.encode_PduSessionResourceSetupResponseTransfer(**kwargs)
            else:
                print(self.encode_PduSessionResourceSetupResponseTransfer.__doc__)
                return 0
        else:
            logger.error(f"msg_type {msg_to_encode} is undefined")
            return 0

        print(f"Encoded Value is: {ret}")



    def encode_PduSessionResourceSetupRequestTransfer(self, **kwargs):
        """
        Pass values to encode PDU Session Rsrc Setup Req and return a hex stream

        Keys/Args:

        ambr     : { 1 : <AMBR_DL>, 2: <AMBR_UL> } In Integer
        pdu_typ  : can be ipv4,ipv6, ipv4v6, ethernet, unstructured
        gtp_tunn : { 1 : <IP BIT string>, 2: <TEID as string without 0x>}
        addn_ul_tunn : is same as above gtp_tunn
        qfi : (List) in format [ { 1: <QFI>, 2: 5QI, 3: prior level, 4: preemptCapability, 5: vulnerability} ]
            5QI in INT
            prior level in INT
            premptCapabiltiy     shall-not-trigger-pre-emption or may-trigger-pre-emption
            vulnerability       not-pre-emptable or pre-emptable
        data_fwd_np : if anything other than none, this flag is set 
        """

        self.debug       = kwargs['debug']    if 'debug'     in kwargs else None
        self.ambr        = kwargs['ambr']     if 'ambr'      in kwargs else None
        self.pdu_typ     = kwargs['pdu_typ']  if 'pdu_typ'   in kwargs else None
        self.gtp_tunn    = kwargs['gtp_tunn'] if 'gtp_tunn'  in kwargs else None
        self.qfi         = kwargs['qfi']      if 'qfi'       in kwargs else None
        self.addn_ul_tunn = kwargs['addn_ul_tunn']  if 'addn_ul_tunn' in kwargs else None
        self.data_fwd_np = kwargs['data_fwd_np'] if 'data_fwd_np'  in kwargs else None
        
        encodePSRSReqTransfer = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupRequestTransfer
        if self.debug == 'true':
            logging.debug(encodePSRSReqTransfer.get_proto())

        # We need to build protocolIEs
        # for ie in NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupRequestTransferIEs().root: print(ie)
        '''
        {'id': 130, 'criticality': 'reject', 'Value': <Value ([PDUSessionAggregateMaximumBitRate] SEQUENCE)>, 'presence': 'optional'}
        {'id': 139, 'criticality': 'reject', 'Value': <Value ([UPTransportLayerInformation] CHOICE)>, 'presence': 'mandatory'}
        {'id': 126, 'criticality': 'reject', 'Value': <Value ([UPTransportLayerInformation] CHOICE)>, 'presence': 'optional'}
        {'id': 127, 'criticality': 'reject', 'Value': <Value ([DataForwardingNotPossible] ENUMERATED)>, 'presence': 'optional'}
        {'id': 134, 'criticality': 'reject', 'Value': <Value ([PDUSessionType] ENUMERATED)>, 'presence': 'mandatory'}
        {'id': 138, 'criticality': 'reject', 'Value': <Value ([SecurityIndication] SEQUENCE)>, 'presence': 'optional'}
        {'id': 129, 'criticality': 'reject', 'Value': <Value ([NetworkInstance] INTEGER)>, 'presence': 'optional'}
        {'id': 136, 'criticality': 'reject', 'Value': <Value ([QosFlowSetupRequestList] SEQUENCE OF)>, 'presence': 'mandatory'}
        '''

        IEs = [] # let's build the list of IEs values

        if self.addn_ul_tunn is not None:
            addr = self.addn_ul_tunn['1']
            teid = unhexlify(self.addn_ul_tunn['2'])
            IEs.append({'id': 126, 'criticality': 'reject', 
                'value': ('UPTransportLayerInformation', 
                    ('gTPTunnel', {'transportLayerAddress': (int(addr), 160), 'gTP-TEID': teid }))})
            logger.warning("Additional UL transport info NOT implemented")

        if self.data_fwd_np is not None:
            IEs.append({'id': 127, 'criticality': 'reject', 'value': ('DataForwardingNotPossible', 'data-forwarding-not-possible')})
            

        if self.ambr is not None:
            #ambr is a tuple with val <DL>, <UL>
            ambr_dl = self.ambr['1']
            ambr_ul = self.ambr['2']
            IEs.append({'id': 130, 'criticality': 'reject', 
                'value': ('PDUSessionAggregateMaximumBitRate', 
                    {'pDUSessionAggregateMaximumBitRateDL': ambr_dl, 
                    'pDUSessionAggregateMaximumBitRateUL': ambr_ul }
                        )})
        
        if self.pdu_typ is not None:
            IEs.append({'id': 134, 'criticality': 'reject', 'value': ('PDUSessionType', self.pdu_typ)})

        if self.qfi is not None:
            #QFI is a list of { <QFI>, 5QI, prior level, preemptCapability, vulnerability}}
            tmp = []
            for qfiLst in self.qfi:
                tmp.append({ 'qosFlowIdentifier': int(qfiLst['1']), 'qosFlowLevelQosParameters': { 'qosCharacteristics': ('nonDynamic5QI', {'fiveQI': int(qfiLst['2'])}), 'allocationAndRetentionPriority': { 'priorityLevelARP': int(qfiLst['3']), 'pre-emptionCapability': qfiLst['4'], 'pre-emptionVulnerability': qfiLst['5'] } } })
            IEs.append({'id': 136, 'criticality': 'reject', 
                'value': ('QosFlowSetupRequestList', tmp ) })

        
        if self.gtp_tunn is not None:
            #gtp_tunn is a tuple with values <IP BIT string>,<TEID as string without 0x>
            addr = self.gtp_tunn['1']
            teid = unhexlify(self.gtp_tunn['2'])
            IEs.append({'id': 139, 'criticality': 'reject', 
                'value': ('UPTransportLayerInformation', 
                    ('gTPTunnel', {'transportLayerAddress': (int(addr), 160), 'gTP-TEID': teid }))})


        val = { 'protocolIEs': IEs }
        
        try:
            encodePSRSReqTransfer.set_val(val)
        except:
            logger.exception("Error Setting values for PDU Sess Setup")
            logger.debug(f"List: {val}")
            return 0

        if self.debug == 'true':
            logger.debug(encodePSRSReqTransfer.to_asn1())
            print(encodePSRSReqTransfer.to_asn1())

        try:
            ret = hexlify(encodePSRSReqTransfer.to_aper())
        except:
            logger.exception("Tried to Encode PDU Session Setup Req")
            return 0
        else:
            return ret

    def test_setup_response(self):
        test = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupResponseTransfer
        print(test)
        #help(test)
        test.from_aper(unhexlify('0003e006070901100000010005'))
        print(test())
        #<PDUSessionResourceSetupResponseTransfer (SEQUENCE)>
        #{'qosFlowPerTNLInformation': {'uPTransportLayerInformation': 
        #('gTPTunnel', {'transportLayerAddress': (101124353, 32), 'gTP-TEID': b'\x10\x00\x00\x01'}), 'associatedQosFlowList': [{'qosFlowIdentifier': 5}]}}
        print(test.to_asn1())
        print(utils.get_obj_at( test, ['qosFlowPerTNLInformation']))
        print(test.get_at(['qosFlowPerTNLInformation']))
        #<qosFlowPerTNLInformation ([QosFlowPerTNLInformation] SEQUENCE)>
        #<qosFlowPerTNLInformation ([QosFlowPerTNLInformation] SEQUENCE)>

        t = {'qosFlowPerTNLInformation': {'uPTransportLayerInformation': ('gTPTunnel', {'transportLayerAddress': (101124353, 32), 'gTP-TEID': b'\x10\x00\x00\x01'}), 'associatedQosFlowList': [{'qosFlowIdentifier': 5}]}}
        test.set_val(t)        
        print(hexlify(test.to_aper()))



    def encode_PduSessionResourceSetupResponseTransfer(self, **kwargs):
        """
        Pass values to encode PDU Session Rsrc Setup Respone and return a hex stream

        {
            "msg_type" : "PDU_SESS_RSRC_SETUP_RSP",
            "qos_per_tunn" : { 
                "1": "101124353", 
                "2": "10000001", 
                "3": 5 },
            "addn_qos_tunn" : { 
                "1": "101124353", 
                "2": "10000001", 
                "3": 5 },
            "sec_result" : {
                "1": "performed",
                "2": "performed"},
            "qos_failed_lst" : [{ "1": "5", "2": "deregister"}, 
                                { "1": "6", "2": "normal-release"}] 
        }

        Keys/Args:

        qos_per_tunn  -
        addn_qos_tunn - Dict is of type (address, teid, QFI)
                        {"1": <address as bit string>, "2": <TEID without0x>, "3": <OFI>}
        sec_result    - {"1": <intergrityProtection>, "2": <confidentialityprotection>}
                        confidentialityProtection:
                        IntegrityProtection:
                            performed / not-performed
        qos_failed_lst - Lists of Dicts. Each Dict of type ("1": <QFI>, "2":<cause>). Only nas cause supported
                        nas causes:
                            normal-release,
                            authentication-failure,
                            deregister,
                            unspecified,
        """

        self.debug          = kwargs['debug']           if 'debug'          in kwargs else None
        self.qos_per_tunn   = kwargs['qos_per_tunn']    if 'qos_per_tunn'   in kwargs else None
        self.addn_qos_tunn  = kwargs['addn_qos_tunn']   if 'addn_qos_tunn'  in kwargs else None
        self.sec_result     = kwargs['sec_result']      if 'sec_result'     in kwargs else None
        self.qos_failed_lst = kwargs['qos_failed_lst']  if 'qos_failed_lst' in kwargs else None

        encodePSRSRespTransfer = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupResponseTransfer

        if self.debug ==  'true':
            logger.debug(encodePSRSRespTransfer._cont)
            logger.debug(encodePSRSRespTransfer.get_proto())
        """
        {
        qosFlowPerTNLInformation: <qosFlowPerTNLInformation ([QosFlowPerTNLInformation] SEQUENCE)>,
        additionalQosFlowPerTNLInformation: <additionalQosFlowPerTNLInformation ([QosFlowPerTNLInformation] SEQUENCE)>,
        securityResult: <securityResult ([SecurityResult] SEQUENCE)>,
        qosFlowFailedToSetupList: <qosFlowFailedToSetupList ([QosFlowList] SEQUENCE OF)>,
        iE-Extensions: <iE-Extensions ([ProtocolExtensionContainer] SEQUENCE OF)>
        }

        IEs.asn
        PDUSessionResourceSetupResponseTransfer ::= SEQUENCE {
            qosFlowPerTNLInformation				QosFlowPerTNLInformation,
            additionalQosFlowPerTNLInformation		QosFlowPerTNLInformation											OPTIONAL,
            securityResult							SecurityResult														OPTIONAL,
            qosFlowFailedToSetupList				QosFlowList															OPTIONAL,
            iE-Extensions		ProtocolExtensionContainer { {PDUSessionResourceSetupResponseTransfer-ExtIEs} }		OPTIONAL,
            ...
        }
        """

        IEs = {} # let's build the list of IEs values

        if self.qos_per_tunn is not None:
            addr = self.qos_per_tunn["1"]
            teid = unhexlify(self.qos_per_tunn["2"])
            qfi = int(self.qos_per_tunn["3"])
            #IEs = {'qosFlowPerTNLInformation': {'uPTransportLayerInformation': 
            #        ('gTPTunnel', {'transportLayerAddress': (int(addr), 32), 'gTP-TEID': teid }), 'associatedQosFlowList': [{'qosFlowIdentifier': qfi}]}}
            IEs['qosFlowPerTNLInformation'] = {'uPTransportLayerInformation': 
                    ('gTPTunnel', {'transportLayerAddress': (int(addr), 32), 'gTP-TEID': teid }), 'associatedQosFlowList': [{'qosFlowIdentifier': qfi}]}
            #debugger.set_trace()

        if self.addn_qos_tunn is not None:
            addr = self.addn_qos_tunn["1"]
            teid = unhexlify(self.addn_qos_tunn["2"])
            qfi = int(self.addn_qos_tunn["3"])
            IEs['additionalQosFlowPerTNLInformation'] = {'uPTransportLayerInformation': 
                    ('gTPTunnel', {'transportLayerAddress': (int(addr), 32), 'gTP-TEID': teid }), 'associatedQosFlowList': [{'qosFlowIdentifier': qfi}]}
            #debugger.set_trace()

        if self.sec_result is not None:
            ip_result   = self.sec_result["1"]
            conf_result = self.sec_result["2"]
            IEs['securityResult'] = {'integrityProtectionResult': ip_result, 'confidentialityProtectionResult': conf_result}

        #9.3.1.13 38.413
        if self.qos_failed_lst is not None:
            tmp = []
            #it is a list of { QFI, cause}, only nas cause supported
            for flow_item in self.qos_failed_lst:
                tmp.append( {'qosFlowIdentifier': int(flow_item["1"]), 'cause': ('nas', flow_item["2"]) })

            IEs['qosFlowFailedToSetupList'] = tmp


        try:
            encodePSRSRespTransfer.set_val(IEs)
        except:
            logger.exception("Error setting values for PDU Sess Setup Resp Transfer")
            logger.debug(f"Array: {IEs}")
            return 0

        try:
            ret = hexlify(encodePSRSRespTransfer.to_aper())
            if self.debug == 'true':
                print(hexlify(encodePSRSRespTransfer.to_aper()))

        except:
            logger.exception("Tried Encoding PDU Sess Setup Resp Transfer")
        else:
            return ret






if __name__ ==  "__main__" :    
    #test()
    #testPcch()
    #encode_PduSessionResourceSetupRequestTransfer_2()

    #Dummy call
    n2Obj = N2Decoder()
    #decoded_bytes = n2Obj.encode_PduSessionResourceSetupRequestTransfer( ambr = (6000000,6000000), 
    #    pdu_typ = 'ipv4', qfi = [('5', '5', '9', 'shall-not-trigger-pre-emption', 'not-pre-emptable')],
    #    gtp_tunn = ('98615294594055401567350253808623404875904323600', '40010105') )
    
    #print(decoded_bytes)
    #n2Obj.test_setup_response()
    #n2Obj.encode_PduSessionResourceSetupResponseTransfer( qos_per_tunn = ( '101124353', '10000001', 5 ))


    ########################
    # PDU Session rsrc Setup response
    ########################
    #n2Obj.encode_PduSessionResourceSetupResponseTransfer( qos_per_tunn = ( '101124353', '10000001', 5 ), addn_qos_tunn = ( '101124353', '10000001', 5 ), 
    #            sec_result = ('performed','performed'), qos_failed_lst = [('5', 'deregister'), ('6', 'normal-release')] )
    #7003e006070901100000010005007c0607090110000001000500102a406400

    #n2Obj.encode_PduSessionResourceSetupResponseTransfer( qos_per_tunn = ( '101124353', '10000001', 5 ), sec_result = ('performed','performed'), qos_failed_lst = [('5', 'deregister'), ('6', 'normal-release')])
    #3003e00607090110000001000500102a406400
