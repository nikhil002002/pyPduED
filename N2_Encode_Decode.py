#!/usr/bin/env python

import sys, getopt
import re
import pdb as debugger
import N2_Decoder
import logging
import json

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# Create handlers
f_handler = logging.FileHandler('n2EncoderDecoder.log', 'w')
f_handler.setLevel(logging.DEBUG)
# Create formatters and add it to handlers
f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
f_handler.setFormatter(f_format)
# Add handlers to the logger
logger.addHandler(f_handler)


def print_help(opr_typ):
    """
    """
    print("The Command can be used as N2_Encode_Decode <opr> [-i|--inputFile] [x|hex]")
    print("<opr> can be encode or decode")
    print("-i|--inputFile is the json file that contain the various opts in Json format to be used incase the opr is encode")
    print(" x|--hex is the hex string in case opr is decode ")

    if opr_typ == "encode":
        print(N2_Decoder.N2Decoder.start_encode.__doc__)
    #if opr_typ == "decode":
        #print(N2_Decoder.N2Decoder.start_decode.__doc__)


def is_hex(inp):
    return re.fullmatch(r"^[0-9a-fA-F]+$", inp or "") is not None


def n2_encoder_invoke(file_name):

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
    


def n2_decoder_invoke(file_name):

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

    #validate Input is only Hex
    if len(sys.argv) < 2 :
        print("Script needs atleast one argument encode/decode")
        sys.exit()

    try:
        opts, args = getopt.getopt(sys.argv[2:],'i:x:',["help","inputFile=","hex="])
    except getopt.GetoptError:
        print("Incorrect usage. Check help using --help")
        sys.exit()

    for opt, val in opts:
        if opt in ("-h", "--help"):
            print_help(sys.argv[1])
            sys.exit()
        

    if sys.argv[1] == 'encode':
        for opt, val in opts:
            if "-i" in opt or "--inputFile" in opt:
                n2_encoder_invoke(val)
                sys.exit()
        print("Check Help. you need to pass a file with input parameters")

    elif sys.argv[1] == 'decode':
        for opt, val in opts:
            if "-i" in opt or "--inputFile" in opt:
                n2_decoder_invoke(val)
                sys.exit()
        print("Check Help. you need to pass a fil with hex string to decode")



if __name__ ==  "__main__" :
    main_function()