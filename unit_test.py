from sys import exit

import re
import sys
import math

def parseBraces(line, braces):
    if "{" in line:
        braces.append("{")
    elif "}" in line:
        if braces[-1] != "{":
            print("invalid brackets")
            exit(1)
        else:
            braces.pop()
            if (len(braces) == 0):
                return True
    
    return False

def extract_param(fileName):
    charBuf = []
    charBufLen = []

    param = []

    charReg = re.compile(r'static unsigned char ([\w]+)\[([\w]+)\] *;')
    paramReg = re.compile(r'static auth_param_type_desc_t ([\w]+) *=')
    certReg = re.compile(r'static const auth_img_desc_t ([\w]+) *=')
    
    for line in fileName:
        match = charReg.match(line)
        if match != None:
            name, len = match.groups()
            charBuf.append(name)
            charBufLen.append(len)

        match = paramReg.match(line)
        if match != None:
            param.append(match.groups()[0])
        
        match = certReg.match(line)
        if match != None:
            return charBuf, charBufLen, param, match.groups()[0]
        
    return charBuf, charBufLen, param, None

def extract_cert(fileName, stack):
    # for line in fileName:
    #     if parseBraces(line, stack):
    #         return True
    # return False
    return

def extract_certs(fileName, firstCert):
    certs = [firstCert]
    stack = ["{"]

    certReg = re.compile(r'static const auth_img_desc_t ([\w]+) *= *{')
    cotReg = re.compile(r'static const auth_img_desc_t \* const cot_desc\[\]')
    pkgReg1 = re.compile(r'DEFINE_SIP_SP_PKG\(([\d]+)\);')
    pkgReg2 = re.compile(r'DEFINE_PLAT_SP_PKG\(([\d]+)\);')

    for line in fileName:
        match = certReg.search(line)
        if match != None:
            certs.append(match.groups()[0])
            extract_cert(fileName, stack)
            continue

        match = pkgReg1.search(line)
        if match != None:
            name = "sp_pkg" + match.groups()[0]
            if name not in certs:
                certs.append(name)

        match = pkgReg2.search(line)
        if match != None:
            name = "sp_pkg" + match.groups()[0]
            if name not in certs:
                certs.append(name)
        
        match = cotReg.search(line)
        if match != None:
            return certs

    return certs

def extract_cot(fileName):
    cotReg = re.compile(r'\[([\w]+)\][\t ]*=[\t ]*&([\w]+)')
    id = []
    value = []

    for line in fileName:
        match = cotReg.search(line)
        if match != None:
            word1, word2 = match.groups()
            id.append(word1)
            value.append(word2)

    return id, value

def main():
    ref = open(sys.argv[1])
    test = open(sys.argv[2])

    refCharBuf, refCharBufLen, refParam, refFirstCert = extract_param(ref)
    testCharBuf, testCharBuflen, testParam, testfirstCert = extract_param(test)

    refCerts = extract_certs(ref, refFirstCert)
    testCerts = extract_certs(test, testfirstCert)
    
    refCotKey, refCotValue = extract_cot(ref)
    testCotKey, testCotValue = extract_cot(test)

    charBufMissing = []
    charBufExtra = []

    for i in refCharBuf:
        if i not in testCharBuf:
            charBufMissing.append(i)

    for i in testCharBuf:
        if i not in refCharBuf:
            charBufExtra.append(i)

    if len(charBufMissing) != 0:
        print("testing char buffer missing:")
        print(charBufMissing)

    if len(charBufExtra) != 0:
        print("testing char buf extra:")
        print(charBufExtra)

    paramMissing = []
    paramExtra = []

    for i in refParam:
        if i not in testParam:
            paramMissing.append(i)
    
    for i in testParam:
        if i not in refParam:
            paramExtra.append(i)

    if len(paramMissing) != 0:
        print("testing param missing:")
        print(paramMissing)

    if len(paramExtra) != 0:
        print("testing param extra:")
        print(paramExtra)

    certMissing = []
    certExtra = []

    for i in refCerts:
        if i not in testCerts:
            certMissing.append(i)
    
    for i in testCerts:
        if i not in refCerts:
            certExtra.append(i)

    if len(certMissing) != 0:
        print("testing cert missing:")
        print(certMissing)

    if len(certExtra) != 0:
        print("testing cert extra:")
        print(certExtra)

    cotMissing = []
    cotExtra = []

    for i in refCotKey:
        if i not in testCotKey:
            cotMissing.append(i)

    for i in testCotKey:
        if i not in refCotKey:
            cotExtra.append(i)

    if len(cotMissing) != 0:
        print("testing cot missing:")
        print(cotMissing)

    if len(cotExtra) != 0:
        print("testing cot extra:")
        print(cotExtra)

    return

if __name__=="__main__": 
    if (len(sys.argv) < 3):
        print("usage: python3 " + sys.argv[0] + " [reference file path] [output c file path]")
        exit()
    main() 