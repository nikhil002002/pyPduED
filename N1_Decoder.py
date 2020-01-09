import sys
import getopt
import re
import pdb as debugger
import logging

import pycrate_mobile

from binascii import unhexlify
from binascii import hexlif

#print (parse_NAS5G(unhexlify('2e0101c1ffff91'), inner=False, sec_hdr=False))

#print()
#print()
#print()
#
#element, err = parse_NAS5G(unhexlify('2e0100cb7a001302001021310b100f010102ffffffff30117f0279001a02204501010302030600050303060006040306000a050306000f'), inner=False, sec_hdr=False)
#
#show(element)


def n1_decode(**kwargs):
    """
    """

    if hex' in kwargs:
        hex_ip = kwargs['hex']
    else:
        logger.error("The Config file did not have a key for\
            a hex value. You need to pass the hex you want to decode")
        return

    logger.info(f"Starting Decode of N1 HexStream {hex_ip}")

    #    inner: if True, decode NASMessage within security header if possible
    #                    
    #    sec_hdr: if True, handle the 5GMM security header
    #            otherwise, just consider the NAS message is in plain text
    
    element, err = parse_NAS5G(unhexlify(hex_ip, inner=False, sec_hdr=False))

    if (err == 0):
        return show(element)
    else:
        logger.error("Could not parse N1 Hex")
        logger.Debug(f"N1 Hex: {hex_ip}")