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


#logger.setLevel(logging.DEBUG)
# Create handlers
#f_handler = logging.FileHandler('n2EncoderDecoder.log', 'a')
#f_handler.setLevel(logging.DEBUG)
# Create formatters and add it to handlers
#f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#f_handler.setFormatter(f_format)
# Add handlers to the logger
#logger.addHandler(f_handler)


def test():
    t = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupRequestTransfer
    print(t)
    #help(t)
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

        Usage: N2_Encode_Decode.py decode -i sample_config.json

        Supported message types:
            PDU_SESS_RSRC_SETUP_REQ
            PDU_SESS_RSRC_SETUP_RSP
            PDU_SESS_RSRC_MOD_REQ
            PDU_SESS_RSRC_MOD_RSP#
            PDU_SESS_RSRC_NOTF#
            PDU_SESS_RSRC_MOD_IND#
            PDU_SESS_RSRC_MOD_CONF
            PATH_SW_REQ
            PATH_SW_REQ_ACK
            HANDOVER_CMD
            HANDOVER_REQ_ACK#
            PDU_SESS_RSRC_REL_CMD
            PDU_SESS_RSRC_NOTF_REL
            HANDOVER_REQUIRED#
            PATH_SW_REQ_SETUP_FAIL
            PDU_SESS_RSRC_SETUP_UNSUCESS
            PDU_SESS_RSRC_MOD_UNSUCESS
            HANDOVER_PREP_UNSUCESS
            HANDOVER_RSRC_ALLOC_UNSUCESS
            PATH_SW_REQ_UNSUCESS
            PDU_SESS_RSRC_REL_RESP#
        """

        if 'msg_type' in kwargs and 'hex' in kwargs:
            msg_to_decode = kwargs['msg_type']
            hex_ip = kwargs['hex']
        else:
            logger.error("The Config file did not have a key for msg_type and\
                a hex value. You need to pass the hex and type of message you want to decode")
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

        elif msg_to_decode == 'PATH_SW_REQ':
            ret = self.decode_PathSwitchRequestTransfer(hex_ip)
        
        elif msg_to_decode == 'PATH_SW_REQ_ACK':
            ret = self.decode_PathSwitchRequestAcknowledgeTransfer(hex_ip)
        
        elif msg_to_decode == 'HANDOVER_CMD':
            ret = self.decode_HandoverCommandTransfer(hex_ip)

        elif msg_to_decode == 'HANDOVER_REQ_ACK':
            ret = self.decode_HandoverRequestAcknowledgeTransfer(hex_ip)

        elif msg_to_decode == 'PDU_SESS_RSRC_REL_CMD':
            ret = self.decode_PduSessionResourceReleaseCommandTransfer(hex_ip)

        elif msg_to_decode == 'PDU_SESS_RSRC_NOTF_REL':
            ret = self.decode_PduSessionResourceNotifyReleasedTransfer(hex_ip)

        elif msg_to_decode == 'HANDOVER_REQUIRED':
            ret = self.decode_HandoverRequiredTransfer(hex_ip)

        elif msg_to_decode == 'PATH_SW_REQ_SETUP_FAIL':
            ret = self.decode_PathSwitchRequestSetupFailedTransfer(hex_ip)

        elif msg_to_decode == 'PDU_SESS_RSRC_SETUP_UNSUCESS':
            ret = self.decode_PDUSessionResourceSetupUnsuccessfulTransfer(hex_ip)

        elif msg_to_decode == 'PDU_SESS_RSRC_MOD_UNSUCESS':
            ret = self.decode_PDUSessionResourceModifyUnsuccessfulTransfer(hex_ip)

        elif msg_to_decode == 'HANDOVER_PREP_UNSUCESS':
            ret = self.decode_HandoverPreparationUnsuccessfulTransfer(hex_ip)

        elif msg_to_decode == 'HANDOVER_RSRC_ALLOC_UNSUCESS':
            ret = self.decode_HandoverResourceAllocationUnsuccessfulTransfer(hex_ip)

        elif msg_to_decode == 'PDU_SESS_RSRC_REL_RESP':
            ret = self.decode_PDUSessionResourceReleaseResponseTransfer(hex_ip)

        else:
            logger.error(f"msg_type {msg_to_decode} is undefined")
            return 0

        print(f"Decoded Value is: {ret}")




    def decode_PduSessionResourceSetupRequestTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Setup Response Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupRequestTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Setup Transfer Req.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret


    def decode_PduSessionResourceSetupResponseTransfer(self, hexString, **kwargs):

        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupResponseTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Response Transfer Req.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret




    def decode_PduSessionResourceModifyRequestTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Setup Resource Modify Request Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceModifyRequestTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Modify Req transfer.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PduSessionResourceModifyResponseTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Setup Resource Modify Response Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceModifyResponseTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Modify Resp Transfer.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PduSessionResourceNotifyTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Setup Resource Notify Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceNotifyTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Rsrc Notify Transfer.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PduSessionResourceModifyIndicationTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Resource Modify Indication Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceModifyIndicationTransfer
        if debug == "true":
            logger.debug(decode_obj)

        #help(t)
        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Rsrc Modify Indication Transfer.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret




    def decode_PduSessionResourceModifyConfirmTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Resource Modify Confirm Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceModifyConfirmTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for PDU Sess Rsrc Modify Confirm Transfer.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret


    def decode_PathSwitchRequestTransfer(self, hexString, **kwargs):
        """
        Decoder for Path Switch Request Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PathSwitchRequestTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for Path Switch Request Transfer.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PathSwitchRequestAcknowledgeTransfer(self, hexString, **kwargs):
        """
        Decoder for Path Switch Request Acknowledge Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PathSwitchRequestAcknowledgeTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for Path Switch Request Acknowledge Transfer.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret


    def decode_HandoverCommandTransfer(self, hexString, **kwargs):
        """
        Decoder for Handover Command Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.HandoverCommandTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for Handover Command Transfer.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret


    def decode_HandoverRequestAcknowledgeTransfer(self, hexString, **kwargs):
        """
        Decoder for Handover Request Ack Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.HandoverRequestAcknowledgeTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for Handover Req Ack Transfer.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret


    def decode_PduSessionResourceReleaseCommandTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Resource Release Command Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceReleaseCommandTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for\
                PDU Session Resource Release CMD Transfer.\
                Try Decoding using the Online tool.\
                If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PduSessionResourceNotifyReleasedTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Resource Notify Released Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceNotifyReleasedTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for\
                PDU Session Resource Notify Released Transfer.\
                Try Decoding using the Online tool.\
                If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret


    def decode_HandoverRequiredTransfer(self, hexString, **kwargs):
        """
        Decoder for Handover Required Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.HandoverRequiredTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for Handover Required Transfer.\
                Try Decoding using the Online tool. If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PathSwitchRequestSetupFailedTransfer(self, hexString, **kwargs):
        """
        Decoder for Path Switch Request Setup Failed Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PathSwitchRequestSetupFailedTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for\
                Path Switch Request Setup Failed Transfer.\
                Try Decoding using the Online tool.\
                If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret


    def decode_PDUSessionResourceSetupUnsuccessfulTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Resource Setup Unsuccessful Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceSetupUnsuccessfulTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for\
                PDU Session Resource Setup Unsuccessful Transfer.\
                Try Decoding using the Online tool.\
                If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PDUSessionResourceModifyUnsuccessfulTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Resource Modify Unsuccessful Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceModifyUnsuccessfulTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for\
                PDU Session Resource Modify Unsuccessful Transfer.\
                Try Decoding using the Online tool.\
                If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_HandoverPreparationUnsuccessfulTransfer(self, hexString, **kwargs):
        """
        Decoder for Handover Preparation Unsuccessful Transfer
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.HandoverPreparationUnsuccessfulTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for\
                Handover Preparation Unsuccessful Transfer.\
                Try Decoding using the Online tool.\
                If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret




    def decode_HandoverResourceAllocationUnsuccessfulTransfer(self, hexString, **kwargs):
        """
        Decoder for Handover Resource Allocation Unsuccessful Transfer 
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.HandoverResourceAllocationUnsuccessfulTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for\
                Handover Resource Allocation Unsuccessful Transfer.\
                Try Decoding using the Online tool.\
                If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret


    def decode_PathSwitchRequestUnsuccessfulTransfer(self, hexString, **kwargs):
        """
        Decoder for Path Switch Request Unsuccessful Transfer 
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PathSwitchRequestUnsuccessfulTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for\
                Path Switch Request Unsuccessful Transfer.\
                Try Decoding using the Online tool.\
                If it works then it is a concern!")
            print("Could Not Decode. Some Exception")
            ret = ""

        return ret



    def decode_PDUSessionResourceReleaseResponseTransfer(self, hexString, **kwargs):
        """
        Decoder for PDU Session Resource Release Response Transfer 
        """
        debug = kwargs['debug']    if 'debug'     in kwargs else None

        decode_obj = NGAP_DEC.NGAP_IEs.PDUSessionResourceReleaseResponseTransfer
        if debug == "true":
            logger.debug(decode_obj)

        try:
            decode_obj.from_aper(unhexlify(hexString))
            #ret = decode_obj.to_asn1()
            ret = decode_obj.to_json()
        except Exception:
            logger.exception("Error in Decoding Hex for\
                PDU Session Resource Release Response Transfer.\
                Try Decoding using the Online tool.\
                If it works then it is a concern!")
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

        for what keys can be used as arguments for encoding a particular message\
        check out the detailed help command
        To use the detailed help command, in the config file,\
        set msg_typ to one of the below supported types
        and give a second key "help" : "true"
        
        Supported message types:
        PDU_SESS_RSRC_SETUP_REQ
        PDU_SESS_RSRC_SETUP_RSP
        PATH_SW_REQ
        HANDOVER_REQ_ACK
        HANDOVER_PREP_UNSUCESS
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
            if help_flag != 1:
                ret = self.encode_PduSessionResourceSetupRequestTransfer(**kwargs)
            else:
                print(self.encode_PduSessionResourceSetupRequestTransfer.__doc__)
                return 0

        elif msg_to_encode == 'PDU_SESS_RSRC_SETUP_RSP':
            if help_flag != 1:
                ret = self.encode_PduSessionResourceSetupResponseTransfer(**kwargs)
            else:
                print(self.encode_PduSessionResourceSetupResponseTransfer.__doc__)
                return 0

        elif msg_to_encode == 'PATH_SW_REQ':
            if help_flag != 1:
                ret = self.encode_PathSwithRequestTransfer(**kwargs)
            else:
                print(self.encode_PathSwithRequestTransfer.__doc__)
                return 0

        elif msg_to_encode == 'HANDOVER_REQ_ACK':
            if help_flag != 1:
                ret = self.encode_HandoverReqAckTransfer(**kwargs)
            else:
                print(self.encode_HandoverReqAckTransfer.__doc__)
                return 0

        elif msg_to_encode == 'HANDOVER_REQUIRED':
            if help_flag != 1:
                ret = self.encode_HandoverRequiredTransfer(**kwargs)
            else:
                print(self.encode_HandoverRequiredTransfer.__doc__)
                return 0

        elif msg_to_encode == 'HANDOVER_PREP_UNSUCESS':
            if help_flag != 1:
                ret = self.encode_HandoverPreparationUnsuccessfulTransfer(**kwargs)
            else:
                print(self.encode_HandoverPreparationUnsuccessfulTransfer.__doc__)
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


    def encode_PathSwithRequestTransfer(self, **kwargs):
        """
        Pass values to encode Path Switch Request and return a hex stream
        PATH_SW_REQ
        Keys/Args:

        up_transport -  Dict is of type
                    {"1": <address as bit string>, "2": <TEID without0x>}
        tnl_info_reuse - if present (any value), the IE is set to 'true'
        user_plane_sec - Dict is of type
                    { "1" - Integrity Protection result,
                      "2" - Confidentiality Protection result,
                      "3" - Integrity Protection Indication,
                      "4" - Confidentialty Protection Result,
                      "5" - Maximum Integrity protection data rate (optional)
                      }
                      For 1,2: possible values:
                            performed / not-performed
                      For 3,4 : possible values:  
                            required / preferred / not-needed
                      For 5: possible values:
                            bitrate64kbs / maximum-UE-rate

        qos_flow_accept: List of QFIs (1, 2, 3...)
        """

        self.debug          = kwargs['debug']           if 'debug'          in kwargs else None
        self.up_transport   = kwargs['up_transport']    if 'up_transport'   in kwargs else None
        self.tnl_info_reuse = kwargs['tnl_info_reuse']  if 'tnl_info_reuse' in kwargs else None
        self.user_plane_sec = kwargs['user_plane_sec']  if 'user_plane_sec' in kwargs else None
        self.qos_flow_accept = kwargs['qos_flow_accept'] if 'qos_flow_accept' in kwargs else None

        encodePathSwitchReqTransfer = NGAP_DEC.NGAP_IEs.PathSwitchRequestTransfer

        if self.debug ==  'true':
            logger.debug(encodePathSwitchReqTransfer._cont)
            logger.debug(encodePathSwitchReqTransfer.get_proto())
        """
        {
        dL-NGU-UP-TNLInformation: <dL-NGU-UP-TNLInformation ([UPTransportLayerInformation] CHOICE)>,
        dL-NGU-TNLInformationReused: <dL-NGU-TNLInformationReused ([DL-NGU-TNLInformationReused] ENUMERATED)>,
        userPlaneSecurityInformation: < ([UserPlaneSecurityInformation] SEQUENCE)>,
        qosFlowAcceptedList: <qosFlowAcceptedList ([QosFlowAcceptedList] SEQUENCE OF)>,
        iE-Extensions: <iE-Extensions ([ProtocolExtensionContainer] SEQUENCE OF)>
        }

        IEs.asn
        PathSwitchRequestTransfer ::= SEQUENCE {
        dL-NGU-UP-TNLInformation			UPTransportLayerInformation,
        dL-NGU-TNLInformationReused			DL-NGU-TNLInformationReused							OPTIONAL,
        userPlaneSecurityInformation		UserPlaneSecurityInformation						OPTIONAL,
        qosFlowAcceptedList					QosFlowAcceptedList,
        iE-Extensions		ProtocolExtensionContainer { {PathSwitchRequestTransfer-ExtIEs} }	OPTIONAL,
        ...
        }
        """

        IEs = {} # let's build the list of IEs values

        if self.up_transport is not None:
            self.addr = self.up_transport["1"]
            upTransport = self.encode_UPTransportLayerInformation(self.addr, self.up_transport["2"])
            #IEs = {'qosFlowPerTNLInformation': {'uPTransportLayerInformation': 
            #        ('gTPTunnel', {'transportLayerAddress': (int(addr), 32), 'gTP-TEID': teid }), 'associatedQosFlowList': [{'qosFlowIdentifier': qfi}]}}
            IEs['dL-NGU-UP-TNLInformation'] = upTransport
            #debugger.set_trace()
        else:
            logger.error("Up Transport information is mandatory")
            return 0

        if self.tnl_info_reuse is not None:
            IEs['dL-NGU-TNLInformationReused'] = "true"

        if self.user_plane_sec is not None:
            self.int_prot_result = self.user_plane_sec["1"]
            self.conf_prot_result = self.user_plane_sec["2"]
            self.int_prot_indication = self.user_plane_sec["3"]
            self.conf_prot_indication = self.user_plane_sec["4"]
            self.max_int_prot_data = self.user_plane_sec["5"]  if "5" in self.user_plane_sec else None

            IEs['userPlaneSecurityInformation'] = self.encode_user_plane_sec_info(self.int_prot_result, 
                self.conf_prot_result, self.int_prot_indication, self.conf_prot_indication, max_int_prot_data=self.max_int_prot_data)

        if self.qos_flow_accept is not None:
            tmp = []
            #it is a list of { QFI }
            for qos in self.qos_flow_accept:
                tmp.append( {'qosFlowIdentifier': int(qos)} )

            IEs['qosFlowAcceptedList'] = tmp
        else:
            logger.error("Accepted list of QOS is mandatory")
            return 0


        try:
            encodePathSwitchReqTransfer.set_val(IEs)
        except:
            logger.exception("Error setting values for Path Switch Request Transfer")
            logger.debug(f"Array: {IEs}")
            return 0

        try:
            ret = hexlify(encodePathSwitchReqTransfer.to_aper())
            if self.debug == 'true':
                print(hexlify(encodePathSwitchReqTransfer.to_aper()))

        except:
            logger.exception("Tried Encoding Path Switch Request Transfer")
        else:
            return ret


    def encode_HandoverRequiredTransfer(self, **kwargs):
        """
        Pass values to encode handover Required Transfer and return a hex stream
            HANDOVER_REQUIRED
        Keys/Args:

        direct_fwd_avail -  true/any value sets IE to direct-path-available
        """

        self.debug            = kwargs['debug']            if 'debug'            in kwargs else None
        self.direct_fwd_avail = kwargs['direct_fwd_avail'] if 'direct_fwd_avail' in kwargs else None

        encodeHandoverRequired = NGAP_DEC.NGAP_IEs.HandoverRequiredTransfer

        if self.debug ==  'true':
            logger.debug(encodeHandoverRequired._cont)
            logger.debug(encodeHandoverRequired.get_proto())

        """
        {
        directForwardingPathAvailability: <directForwardingPathAvailability ([DirectForwardingPathAvailability] ENUMERATED)>,
        iE-Extensions: <iE-Extensions ([ProtocolExtensionContainer] SEQUENCE OF)>
        }
        HandoverRequiredTransfer ::= SEQUENCE {
            directForwardingPathAvailability		DirectForwardingPathAvailability				OPTIONAL,
            iE-Extensions		ProtocolExtensionContainer { {HandoverRequiredTransfer-ExtIEs} }	OPTIONAL,
            ...
        """
        
        IEs = {} # let's build the list of IEs values

        if self.direct_fwd_avail is not None:
            IEs['directForwardingPathAvailability'] = 'direct-path-available'
            #debugger.set_trace()
        else:
            logger.error("Direct forwarding path availabilty is the only IE so must be present")
            return 0

        try:
            encodeHandoverRequired.set_val(IEs)
        except:
            logger.exception("Error setting values for Path Switch Request Transfer")
            logger.debug(f"Array: {IEs}")
            return 0

        try:
            ret = hexlify(encodeHandoverRequired.to_aper())
            if self.debug == 'true':
                print(hexlify(encodeHandoverRequired.to_aper()))

        except:
            logger.exception("Tried Encoding Handover Required Transfer")
        else:
            return ret


    def encode_HandoverReqAckTransfer(self, **kwargs):
        """
        Pass values to encode handover request Acknowledge and return a hex stream
            HANDOVER_REQ_ACK
        """

        self.debug              = kwargs['debug']            if 'debug'            in kwargs else None
        self.up_transport       = kwargs['up_transport']     if 'up_transport'     in kwargs else None
        self.dl_fwd_tunn_info   = kwargs['dl_fwd_tunn_info'] if 'dl_fwd_tunn_info' in kwargs else None
        self.sec_result         = kwargs['sec_result']       if 'sec_result'       in kwargs else None
        self.qos_flow_setup     = kwargs['qos_flow_setup']   if 'qos_flow_setup'   in kwargs else None
        self.qos_failed_lst     = kwargs['qos_failed_lst']   if 'qos_failed_lst'   in kwargs else None
        self.data_fw_rsp        = kwargs['data_fw_rsp']      if 'data_fw_rsp'      in kwargs else None

        encodeHandoverReqAckTransfer = NGAP_DEC.NGAP_IEs.HandoverRequestAcknowledgeTransfer

        if self.debug ==  'true':
            logger.debug(encodeHandoverReqAckTransfer._cont)
            logger.debug(encodeHandoverReqAckTransfer.get_proto())
        """
        {
        dL-NGU-UP-TNLInformation: <dL-NGU-UP-TNLInformation ([UPTransportLayerInformation] CHOICE)>,
        dLForwardingUP-TNLInformation: <dLForwardingUP-TNLInformation ([UPTransportLayerInformation] CHOICE)>,
        securityResult: <securityResult ([SecurityResult] SEQUENCE)>,
        qosFlowSetupResponseList: <qosFlowSetupResponseList ([QosFlowSetupResponseListHOReqAck] SEQUENCE OF)>,
        qosFlowFailedToSetupList: <qosFlowFailedToSetupList ([QosFlowList] SEQUENCE OF)>,
        dataForwardingResponseDRBList: <dataForwardingResponseDRBList ([DataForwardingResponseDRBList] SEQUENCE OF)>,
        iE-Extensions: <iE-Extensions ([ProtocolExtensionContainer] SEQUENCE OF)>
        }

        HandoverRequestAcknowledgeTransfer ::= SEQUENCE {
        dL-NGU-UP-TNLInformation			UPTransportLayerInformation,
        dLForwardingUP-TNLInformation		UPTransportLayerInformation										OPTIONAL,
        securityResult						SecurityResult													OPTIONAL,
        qosFlowSetupResponseList			QosFlowSetupResponseListHOReqAck,
        qosFlowFailedToSetupList			QosFlowList														OPTIONAL,
        dataForwardingResponseDRBList		DataForwardingResponseDRBList									OPTIONAL,
        iE-Extensions		ProtocolExtensionContainer { {HandoverRequestAcknowledgeTransfer-ExtIEs} }	OPTIONAL,
        ...
        }
        """
        IEs = {} # let's build the list of IEs values

        if self.up_transport is not None:
            self.addr = self.up_transport["1"]
            upTransport = self.encode_UPTransportLayerInformation(self.addr, self.up_transport["2"])
            IEs['dL-NGU-UP-TNLInformation'] = upTransport
            #debugger.set_trace()
        else:
            logger.error("Up Transport information is mandatory")
            return 0

        if self.dl_fwd_tunn_info is not None:
            self.addr = self.dl_fwd_tunn_info["1"]
            upTransport = self.encode_UPTransportLayerInformation(self.addr, self.dl_fwd_tunn_info["2"])
            IEs['dLForwardingUP-TNLInformation'] = upTransport
            #debugger.set_trace()

        if self.sec_result is not None:
            IEs['securityResult'] = self.encode_security_result(self.sec_result["1"], self.sec_result["2"])

        if self.qos_flow_setup is not None:
            tmp = []
            #it is a list of { QFI, dataFwdAccepted}
            for entry in self.qos_flow_setup:
                tmp_dict = {}
                tmp_dict['qosFlowIdentifier'] = int(entry["qos"])
                if 'dataFwdAccept' in entry:
                    tmp_dict['dataForwardingAccepted'] = 'data-forwarding-accepted'
                
                tmp.append(tmp_dict)

            IEs['qosFlowSetupResponseList'] = tmp
        else:
            logger.error("Qos Flow Setup response list is mandatory")
            return 0

        if self.qos_failed_lst is not None:
            IEs['qosFlowFailedToSetupList'] = self.encode_QosList(self.qos_failed_lst)

        if self.data_fw_rsp is not None:
            IEs['dataForwardingResponseDRBList'] = self.encode_dataFwdDrbList(self.data_fw_rsp)

        try:
            encodeHandoverReqAckTransfer.set_val(IEs)
        except:
            logger.exception("Error setting values for Handover Request Ack Transfer")
            logger.debug(f"Array: {IEs}")
            debugger.set_trace()
            return 0

        try:
            ret = hexlify(encodeHandoverReqAckTransfer.to_aper())
            if self.debug == 'true':
                print(hexlify(encodeHandoverReqAckTransfer.to_aper()))

        except:
            logger.exception("Tried Encoding Handover Request Ack Transfer")
        else:
            return ret



    def encode_HandoverPreparationUnsuccessfulTransfer(self, **kwargs):
        """
        Pass values to encode handover Perparation Unsuccessful Transfer and 
        return a hex stream
        HANDOVER_PREP_UNSUCESS

        cause -  Dict is of type
                    {"type": type is one of radioNetwork/transport/nas/protocol/misc
                    "value": for the strings that can be used here,
                            check ASN1 spec for below ENUMS
                            CauseRadioNetwork,	CauseTransport, 
                            CauseNas, CauseProtocol, CauseMisc}
        """

        self.debug      = kwargs['debug']     if 'debug'     in kwargs else None
        self.cause      = kwargs['cause']     if 'cause'     in kwargs else None

        encodeHandoverPrepUnsuccessTrnf = NGAP_DEC.NGAP_IEs.HandoverPreparationUnsuccessfulTransfer

        if self.debug ==  'true':
            logger.debug(encodeHandoverPrepUnsuccessTrnf._cont)
            logger.debug(encodeHandoverPrepUnsuccessTrnf.get_proto())
        """
        {
        cause: <cause ([Cause] CHOICE)>,
        iE-Extensions: <iE-Extensions ([ProtocolExtensionContainer] SEQUENCE OF)>
        }
        HandoverPreparationUnsuccessfulTransfer ::= SEQUENCE {
            cause				Cause,
            iE-Extensions		ProtocolExtensionContainer { {HandoverPreparationUnsuccessfulTransfer-ExtIEs} }	OPTIONAL,
            ...
        }
        """
        IEs = {} # let's build the list of IEs values

        if self.cause is not None:
            self.cause_type = self.cause["type"]
            self.cause_val = self.cause["value"]
            IEs['cause'] = self.encode_CauseValue(self.cause_type,self.cause_val)
        else:
            logger.error("Cause field mandatory for Handover prep Unsuccessful Tansfer")
            return 0


        try:
            encodeHandoverPrepUnsuccessTrnf.set_val(IEs)
        except:
            logger.exception("Error setting values for Handover Perparation Unsuccessful Transfer")
            logger.debug(f"Array: {IEs}")
            return 0

        try:
            ret = hexlify(encodeHandoverPrepUnsuccessTrnf.to_aper())
            if self.debug == 'true':
                print(hexlify(encodeHandoverPrepUnsuccessTrnf.to_aper()))

        except:
            logger.exception("Tried Encoding Handover Prep Unsuccessful Transfer")
        else:
            return ret
    



    def encode_dataFwdDrbList(self, list_of_data_fwd_drb):
        """
        SEQUENCE (SIZE(1..maxnoofDRBs)) OF DataForwardingResponseDRBItem
        """
        tmp = []
        #it is a list of { ID, UPTransportLayerInformation, UPTransportLayerInformation}
        for item in list_of_data_fwd_drb:
            tmp_dict = {}
            tmp_dict['dRB-ID'] = int(item["id"])

            if 'dl_tunn_info' in item:
                tmp_lst_tunn_info = item['dl_tunn_info']
                tmp_dict['dLForwardingUP-TNLInformation'] =  self.encode_UPTransportLayerInformation(tmp_lst_tunn_info["1"], tmp_lst_tunn_info["2"])
            
            if 'ul_tunn_info' in item:
                tmp_lst_tunn_info = item['ul_tunn_info']
                tmp_dict['uLForwardingUP-TNLInformation'] =  self.encode_UPTransportLayerInformation(tmp_lst_tunn_info["1"], tmp_lst_tunn_info["2"])
            
            tmp.append(tmp_dict)

        return tmp



    def encode_QosList(self, list_of_qfi_cause):
        """
        Input is a list of QFI and Cause pairs.
        { "qfi" : <value>, "cause_type": <nas, misc...>, "cause_value": <>}
        """
        tmp = []
        for flow_item in list_of_qfi_cause:
            cause_tuple = self.encode_CauseValue(flow_item["cause_type"], flow_item["cause_value"])
            tmp.append( {'qosFlowIdentifier': int(flow_item["qfi"]), 'cause': cause_tuple })

        return tmp


    def encode_UPTransportLayerInformation(self, addr, teid):
        "Return a tuple with Up Transport information"
        teid = unhexlify(teid)
        return ('gTPTunnel', {'transportLayerAddress': (int(addr), 160), 'gTP-TEID': teid })


    def encode_user_plane_sec_info(self, int_prot_result, conf_prot_result,
            int_prot_indication, conf_prot_indication, **kwargs):
        """
        User Plane Security information.
        Has security result and security indication
        """
        max_int_prot_data = kwargs['max_int_prot_data'] if 'max_int_prot_data' in kwargs else None
        IEs = {}
        IEs['securityResult'] = self.encode_security_result(int_prot_result, conf_prot_result)
        IEs['securityIndication'] = self.encode_security_indication(int_prot_indication, 
                                conf_prot_indication, max_int_prot_data = max_int_prot_data)
        
        return IEs


    def encode_security_result(self, int_prot_result, conf_prot_result):
        """
        Encode Security Result
        IntegrityProtectionResult ::= ENUMERATED {
            performed,
            not-performed,
            ...
        }
        ConfidentialityProtectionResult ::= ENUMERATED {
            performed,
            not-performed,
            ...
        }
        """
        IEs = {}
        IEs['integrityProtectionResult'] = int_prot_result
        IEs['confidentialityProtectionResult'] = conf_prot_result
        return IEs


    def encode_security_indication(self, int_prot_indication, conf_prot_indication, **kwargs):
        """
        IntegrityProtectionIndication ::= ENUMERATED {
            required,
            preferred,
            not-needed,
            ...
        }
        ConfidentialityProtectionIndication ::= ENUMERATED {
            required,
            preferred,
            not-needed,
            ...
        }
        MaximumIntegrityProtectedDataRate ::= ENUMERATED {
            bitrate64kbs,
            maximum-UE-rate,
            ...
        }
        """
        ret_val = {'integrityProtectionIndication': int_prot_indication,
                    'confidentialityProtectionIndication': conf_prot_indication }
        if kwargs['max_int_prot_data'] is not None:
            ret_val['maximumIntegrityProtectedDataRate'] = kwargs['max_int_prot_data']

        return ret_val


    def encode_CauseValue(self, cause_type, cause_str):
        """
            Return a tuple with cause
            cause_type can be anyone of the column1 below
            for values, refer to ASN spec and grep for corresponding fields in column2
            	radioNetwork		CauseRadioNetwork,
                transport			CauseTransport,
                nas					CauseNas,
                protocol			CauseProtocol,
                misc				CauseMisc,
        """
        return (cause_type, cause_str)

            #HANDOVER_RSRC_ALLOC_UNSUCESS
            
            #PDU_SESS_RSRC_MOD_RSP#
            #PDU_SESS_RSRC_NOTF#
            #PDU_SESS_RSRC_MOD_IND#
            #HANDOVER_REQ_ACK#
            #PDU_SESS_RSRC_REL_RESP#

if __name__ ==  "__main__" :
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    s_handler = logging.StreamHandler(sys.stdout)
    s_handler.setLevel(logging.DEBUG)
    logger.addHandler(s_handler) 
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

    n2DecodeObj =N2Decoder()
    #n2DecodeObj.encode_PathSwithRequestTransfer(debug = 'true')
    #n2DecodeObj.encode_HandoverReqAckTransfer(debug= 'true')
    #n2DecodeObj.encode_HandoverPreparationUnsuccessfulTransfer(debug='true')
    n2DecodeObj.encode_HandoverRequiredTransfer(debug= 'true')