# -*- coding: UTF-8 -*-
#/**
# * Software Name : pyPdu
# * Version : 0.1
# *
# * Copyright 2019. Nikhil Rajendran
# *
# *--------------------------------------------------------
# * File Name : pyPduED/TS24501_5GSM.py
# * Created : 2019-10-20
# * Authors : Nikhil Rajendran 
# *--------------------------------------------------------
#*/

__all__ = [
    'PDUSessEstablishAccept',
    'get_esm_msg_instances'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.501: NAS protocol for 5GS
# release 15
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from pycrate_mobile.TS24007    import *
#from .TS24301_IE import *

# section 9.8
_FIVEGSM_DICT = {
    # default bearer
    193 : "Activate default EPS bearer context request",
    }


class FiveGSMHeader(Envelope):
    """
    Header Defination for 5g Session m
    """
    _GEN = (
        Uint8('ExtProtDisc', val=2),
        Uint8('PduSessId'),
        Uint8('PTI'),
        Uint8('Type', val=193, dic=_FIVEGSM_DICT)
        )

#------------------------------------------------------------------------------#
# PDU Session Establishment Accept
# TS 24.501, 
#------------------------------------------------------------------------------#

class PDUSessEstablishAccept(Layer3):
    _GEN = (
        FiveGSMHeader(val={'Type':193}),
        Type3V('IntegrityProtDataRate', val={'V':b'\x6f'}, bl={'V':16}, IE=ESMCause()),
        Type4TLV('ProtConfig', val={'T':0x27, 'V':b'\x80'}, IE=ProtConfig()),
        Type4TLV('NBIFOMContainer', val={'T':0x33, 'V':b'\0'}),
        Type6TLVE('ExtProtConfig', val={'T':0x7B, 'V':b'\0'})
        )