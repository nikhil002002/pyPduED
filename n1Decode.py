#####!/usr/bin/env python

import sys, getopt
import re
import pdb as debugger
import N1SMDecoder
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# Create handlers
f_handler = logging.FileHandler('n1Decoder.log', 'w')
f_handler.setLevel(logging.DEBUG)
# Create formatters and add it to handlers
f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
f_handler.setFormatter(f_format)
# Add handlers to the logger
logger.addHandler(f_handler)

logger.info('This is info')
logger.debug('This is debug')
logger.warning('This is a warning')
logger.error('This is an error')

def is_hex(inp):
    return re.fullmatch(r"^[0-9a-fA-F]+$", inp or "") is not None


if __name__ ==  "__main__" :
    """ This gets invoked when file is run in Python shell
    """

    #validate Input is only Hex
    if len(sys.argv) != 2 :
        print("Script accepts one argument which is the Hex string")
        sys.exit()
    
    #print (is_hex("0ad12"))


    input_arg = sys.argv[1]
    if not(is_hex(input_arg)):
        print("Input argument could not be validated as a Hex: {0}".format(sys.argv[1]))
        sys.exit()

    #Now this Hex Can be parsed
    decode_obj = N1SMDecoder.N1SMDecode()
    logger.info(f"Starting Decode of {input_arg}")
    decode_obj.startDecode(input_arg)
    