#!/usr/bin/env python

import sys
import getopt
import re
import pdb as debugger
import logging
import N1SMDecoder

logging.root.setLevel(logging.DEBUG)

logger = logging.getLogger(__name__)
#logger.setLevel(logging.DEBUG)

# Create handlers
#f_handler = logging.FileHandler('n1Decoder.log', 'w')
#f_handler.setLevel(logging.DEBUG)
# Create formatters and add it to handlers
#f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#f_handler.setFormatter(f_format)
# Add handlers to the logger
#logger.addHandler(f_handler)

#logger.info('This is info')
#logger.debug('This is debug')
#logger.warning('This is a warning')
#logger.error('This is an error')


def print_help(opr_typ):
    """
    Main Help Function
    """


def is_hex(inp):
    return re.fullmatch(r"^[0-9a-fA-F]+$", inp or "") is not None


if __name__ == "__main__":
    """ This gets invoked when file is run in Python shell
    """
    main_function()

def main_function():
    """
    Main function call
    """
    debugging_enabled = 0

    if len(sys.argv) < 2:
        print("Script accepts one argument which is - encode/decode")
        sys.exit()

    try:
        opts, args = getopt.getopt(sys.argv[2:], 'i:', ["help", "inputFile=", "debug="])
    except getopt.GetoptError:
        print("Incorrect usage. Check help using --help")
        sys.exit()

    for opt, val in opts:
        if opt in ("-h", "--help"):
            print_help(sys.argv[1])
            sys.exit()
        if opt == '--debug':
            debugging_enabled = 1
            debug_file_loc = val + 'n1EncoderDecoder.log'

            try:
                f_handler = logging.FileHandler(debug_file_loc, 'w')
            except Exception:
                logger.exception("Exception in creating logfile")
                sys.exit()
            else:
                # Create file handlers
                f_handler.setLevel(logging.DEBUG)
                # Create formatters and add it to handlers
                f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                f_handler.setFormatter(f_format)
                # Add handlers to the logger
                logging.root.addHandler(f_handler)
        else:
            s_handler = logging.StreamHandler(sys.stdout)
            s_handler.setLevel(logging.INFO)
            logging.root.addHandler(s_handler)


    if sys.argv[1] == 'encode':
        for opt, val in opts:
            if "-i" in opt or "--inputFile" in opt:
                #TODO
                #n2_encoder_invoke(val, debugging_enabled)
                sys.exit()
        print("Check Help. you need to pass a file with input parameters")

    elif sys.argv[1] == 'decode':
        for opt, val in opts:
            if "-i" in opt or "--inputFile" in opt:
                n1_decoder_invoke(val, debugging_enabled)
                sys.exit()
        print("Check Help. you need to pass a fil with hex string to decode")


    #Now this Hex Can be parsed
    #decode_obj = N1SMDecoder.N1SMDecode()
    #logger.info(f"Starting Decode of {input_arg}")
    #decode_obj.startDecode(input_arg)
    