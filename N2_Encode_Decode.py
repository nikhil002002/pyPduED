#!/usr/bin/env python

import sys
import getopt
import re
import logging
import json
#import pdb as debugger
import N2_Decoder

logging.root.setLevel(logging.DEBUG)

logger = logging.getLogger(__name__)
#logger.setLevel(logging.DEBUG)

def print_help(opr_typ):
    """
    Main Help function
    """
    print("The Command can be used as N2_Encode_Decode <opr> [-i|--inputFile]")
    print("<opr> can be encode or decode")
    print("-i|--inputFile is the json file that contain the various opts in Json format")
    print("Use --debug=<path> to print logs file N2_encode_decode in <path> e.g. --debug=/tmp/")

    if opr_typ == "encode":
        print(N2_Decoder.N2Decoder.start_encode.__doc__)
    if opr_typ == "decode":
        print(N2_Decoder.N2Decoder2.start_decode.__doc__)


def is_hex(inp):
    return re.fullmatch(r"^[0-9a-fA-F]+$", inp or "") is not None


def n2_encoder_invoke(file_name, debugging):

    encode_obj = N2_Decoder.N2Decoder()
    try:
        #Open the Cfg file
        with open(file_name) as fileobject:
            #arguments is a python Dict
            arguments = json.load(fileobject)
    except IOError:
        print("Error opening file {}".format(file_name))
        sys.exit()

    encode_obj.start_encode(**arguments)



def n2_decoder_invoke(file_name, debugging):

    decode_object = N2_Decoder.N2Decoder2()
    try:
        #Open the Cfg file
        with open(file_name) as fileobject:
            #arguments is a python Dict
            arguments = json.load(fileobject)
    except IOError:
        print("Error opening file {}".format(file_name))
        sys.exit()

    decode_object.start_decode(**arguments)


def main_function():
    """ This gets invoked when file is run in Python shell
    """

    debugging_enabled = 0

    #validate Input is only Hex
    if len(sys.argv) < 2:
        print("Script needs atleast one argument encode/decode")
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
            debug_file_loc = val + 'n2EncoderDecoder.log'

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
                n2_encoder_invoke(val, debugging_enabled)

                #logger.info("Hi THis is twst")
                #logger.debug("test")

                sys.exit()
        print("Check Help. you need to pass a file with input parameters")

    elif sys.argv[1] == 'decode':
        for opt, val in opts:
            if "-i" in opt or "--inputFile" in opt:
                n2_decoder_invoke(val, debugging_enabled)
                sys.exit()
        print("Check Help. you need to pass a fil with hex string to decode")



if __name__ == "__main__":
    main_function()
