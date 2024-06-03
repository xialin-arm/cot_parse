from sys import exit

import re
import sys

def removeNumber(s):
    result = ''.join([i for i in s if not i.isdigit()])
    return result

def extractNumber(s):
    for i in s:
        if i.isdigit():
            return (int)(i)
    
    return -1

def peek_line(f):
    pos = f.tell()
    line = f.readline()
    f.seek(pos)
    return line

class authMethod:
    def __init__(self):
        self.type = ""
        self.param = ""
        self.paramKey = []
        self.paramValue = []

    def printInfo(self):
        print("---------- method ------------")
        print("type:", self.type)
        print("param name:", self.param)
        print("param:")
        for i in range(len(self.paramKey)):
            print(self.paramKey[i] + ":", self.paramValue[i])
    
    def init_sign(self):
        self.type = "AUTH_METHOD_SIG"
        self.param = "sig"
        self.paramKey = ["pk", "sig", "alg", "data"]
        self.paramValue = ["", "sig", "sig_alg", "raw_data"]

    def init_hash(self, hash):
        self.type = "AUTH_METHOD_HASH"
        self.param = "hash"
        self.paramKey = ["data", "hash"]
        self.paramValue = ["raw_data", hash]

    def init_nv(self, name):
        self.type = "AUTH_METHOD_NV_CTR"
        self.param = "nv_ctr"
        self.paramKey = ["cert_nv_ctr", "plat_nv_ctr"]
        name = name.replace("counter", "ctr")
        self.paramValue = [name, name]

class authData:
    def __init__(self, type_desc):
        self.type_desc = type_desc
        if "sp_pkg" in type_desc:
            type_desc = removeNumber(type_desc)
        self.ptr = type_desc + "_buf"
        if "pk" in type_desc:
            self.len = "(unsigned int)PK_DER_LEN"
        elif "hash" in type_desc:
            self.len = "(unsigned int)HASH_DER_LEN"
        self.oid = ""

    def printInfo(self):
        print("--------------- data ----------------")
        print("type_desc:", self.type_desc)
        print("oid:", self.oid)
        print("ptr:", self.ptr)
        print("len:", self.len)

class image:
    def __init__(self, imageName):
        self.img_name = imageName
        self.img_id = ""
        self.parent = ""
        self.hash = ""
        self.img_type = "IMG_RAW"
        self.ifdef = ""
        self.img_auth_methods = []

    def printInfo(self):
        print("============== image ==============")
        print("image name:", self.img_name)
        print("image id:", self.img_id)
        print("parent:", self.parent)
        print("hash:", self.hash)

class cert:
    def __init__(self, certName):
        self.cert_name = certName
        self.img_id = ""
        self.img_type = "IMG_CERT"
        self.parent = ""
        self.ifdef = ""
        self.antirollback_counter = ""
        #self.img_auth_methods_name = "(const auth_method_desc_t[AUTH_METHOD_NUM])"
        self.img_auth_methods = []
        #self.authenticated_data_name = "(const auth_param_desc_t[COT_MAX_VERIFIED_PARAMS])"
        self.authenticated_data = []

    def printInfo(self):
        print("===================== cert ======================")
        print("cert:", self.cert_name)
        print("image id:", self.img_id)
        print("image type:", self.img_type)
        print("parent:", self.parent)
        # print("signing key:", self.signing_key)
        print("antirollback:", self.antirollback_counter)
        print("authenticated data:")
        for d in self.authenticated_data:
            d.printInfo()
        for m in self.img_auth_methods:
            m.printInfo()

class generic:
    def __init__(self, name):
        self.name = name
        self.id = ""
        self.oid = ""

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

def extractData(filename, dataName):
    stack = ["{"]
    reg = re.compile(r' *oid *= *([\w]+) *;')

    thisAuthData = authData(dataName)

    for line in filename:
        match = reg.search(line)
        if match != None:
            thisAuthData.oid = match.groups()[0]

        if parseBraces(line, stack):
            #print(thisAuthData.oid)
            return thisAuthData


def extractCert(filename, certName, ifdefFlag, ifdefTag):
    stack = ["{"]
    thisCert = cert(certName)
    if ifdefFlag:
        thisCert.ifdef = ifdefTag

    parent = re.compile(r'parent *= *<&([\w]+)> *;')
    imgidregex = re.compile(r'image-id *= *<([\w]+)> *;')
    keyregex = re.compile(r'signing-key *= *<&([\w]+)> *;')
    antirollbackregex = re.compile(r'antirollback-counter *= *<&([\w]+)> *;')
    dataregex = re.compile(r'([\w]+) *: *([\w]+)')

    #print("cert name:", certName)

    for line in filename:

        if "root-certificate" in line:
            thisCert.parent = "NULL"
            continue

        match = parent.search(line)
        if match != None:
            thisCert.parent = match.groups()[0]
            continue

        match = imgidregex.search(line)
        if match != None:
            thisCert.img_id = match.groups()[0]
            continue
        
        match = keyregex.search(line)
        if match != None:
            thisCert.signing_key = match.groups()[0]
            continue

        match = antirollbackregex.search(line)
        if match != None:
            thisCert.antirollback_counter = match.groups()[0]
            continue

        match = dataregex.search(line)
        if match != None:
            word1, word2 = match.groups()
            thisCert.authenticated_data.append(extractData(filename, word2))
            continue

        
        if parseBraces(line, stack):
            #print("cert done")
            sign = authMethod()
            sign.init_sign()
            thisCert.img_auth_methods.append(sign)
            
            if thisCert.antirollback_counter != "":
                nv = authMethod()
                nv.init_nv(thisCert.antirollback_counter)
                thisCert.img_auth_methods.append(nv)

            return thisCert
        

def manifest(filename, braces):
    certs = []

    reg = re.compile(r'([\w]+) *: *([\w]+)')
    ifdefregex = re.compile(r'#if defined\(([\w]+)\)')
    ifdefend = "#endif"

    ifdefFlag = False
    ifdefTag = ""

    for line in filename:
        match = reg.search(line)

        if match != None:
            word1, word2 = match.groups()
            certs.append(extractCert(filename, word2, ifdefFlag, ifdefTag))

        else:
            match = ifdefregex.search(line)
            if match != None:
                ifdefFlag = True
                ifdefTag = match.groups()[0]

            if ifdefend in line:
                ifdefFlag = False
                ifdefTag = ""

            if parseBraces(line, braces):
                #print("manifests done")
                return certs
        
def extractImage(filename, imageName, ifdefFlag, ifdefTag):
    stack = ["{"]
    thisImage = image(imageName)
    if ifdefFlag:
        thisImage.ifdef = ifdefTag

    parent = re.compile(r'parent *= *<&([\w]+)> *;')
    imgidregex = re.compile(r'image-id *= *<([\w]+)> *;')
    hashregex = re.compile(r'hash *= *<&([\w]+)> *;')

    for line in filename:
        match = parent.search(line)
        if match != None:
            thisImage.parent = match.groups()[0]
            continue

        match = imgidregex.search(line)
        if match != None:
            thisImage.img_id = match.groups()[0]
            continue

        match = hashregex.search(line)
        if match != None:
            thisImage.hash = match.groups()[0]
            continue

        if parseBraces(line, stack):
            m = authMethod()
            m.init_hash(thisImage.hash)
            thisImage.img_auth_methods.append(m)
            return thisImage

def images(filename, braces):
    allImages = []

    reg = re.compile(r'([\w]+) *{')
    ifdefregex = re.compile(r'#if defined\(([\w]+)\)')
    ifdefend = "#endif"

    ifdefFlag = False
    ifdefTag = ""

    for line in filename:
        match = reg.search(line)

        if match != None:
            word = match.groups()[0]
            #print(word)
            allImages.append(extractImage(filename, word, ifdefFlag, ifdefTag))

        else:
            match = ifdefregex.search(line)
            if match != None:
                ifdefFlag = True
                ifdefTag = match.groups()[0]

            if ifdefend in line:
                ifdefFlag = False
                ifdefTag = ""

            if parseBraces(line, braces):
                #print("images done")
                return allImages

def extractOther(filename, name):
    stack = ["{"]

    oid = re.compile(r'oid *= *([\w]+) *;')
    id = re.compile(r'id *= *<([\w]+)> *;')
    
    thisGeneric = generic(name)

    for line in filename:
        match = oid.search(line)
        if match != None:
            thisGeneric.oid = match.groups()[0]
            continue

        match = id.search(line)
        if match != None:
            thisGeneric.id = match.groups()[0]
            continue

        if parseBraces(line, stack):
            return thisGeneric

def Ctrs(filename):
    braces = ["{"]
    ctrs = []

    reg = re.compile(r'([\w]+) *: *([\w]+)')

    for line in filename:
        match = reg.search(line)

        if match != None:
            word1, word2 = match.groups()
            ctrs.append(extractOther(filename, word2))
        else:
            if parseBraces(line, braces):
                return ctrs
        

def PKs(filename):
    braces = ["{"]
    pks = []

    reg = re.compile(r'([\w]+) *: *([\w]+)')

    for line in filename:
        match = reg.search(line)
        if match != None:
            word1, word2 = match.groups()
            pks.append(extractOther(filename, word2))

        else:
            if parseBraces(line, braces):
                return pks


def generateCert(c, f):
    if c.ifdef != "":
        f.write("#if defined({})\n".format(c.ifdef))

    f.write("static const auth_img_desc_t {} = {{\n".format(c.cert_name))
    f.write("\t.img_id = {},\n".format(c.img_id))
    f.write("\t.img_type = {},\n".format(c.img_type))

    if c.parent != "NULL":
        f.write("\t.parent = &{},\n".format(c.parent))
    else:  
        f.write("\t.parent = {},\n".format(c.parent))

    if len(c.img_auth_methods) != 0:
        f.write("\t.img_auth_methods = (const auth_method_desc_t[AUTH_METHOD_NUM]) {\n")
        for i, m in enumerate(c.img_auth_methods):
            f.write("\t\t[{}] = {{\n".format(i))
            
            f.write("\t\t\t.type = {},\n".format(m.type))
            f.write("\t\t\t.param.{} = {{\n".format(m.param))

            for j in range(len(m.paramKey)):
                f.write("\t\t\t\t.{} = &{}{}\n".format(m.paramKey[j], m.paramValue[j], "," if j != len(m.paramKey) - 1 else ""))

            f.write("\t\t\t}\n")
            f.write("\t\t}}{}\n".format("," if i != len(c.img_auth_methods) - 1 else ""))

        f.write("\t}}{}\n".format("," if len(c.authenticated_data) != 0 else ""))

    if len(c.authenticated_data) != 0:
        f.write("\t.authenticated_data = (const auth_param_desc_t[COT_MAX_VERIFIED_PARAMS]) {\n")

        for i, d in enumerate(c.authenticated_data):
            f.write("\t\t[{}] = {{\n".format(i))
            f.write("\t\t\t.type_desc = &{},\n".format(d.type_desc))
            f.write("\t\t\t.data = {\n")
            
            n = extractNumber(d.type_desc)
            if "pkg" not in d.type_desc or n == -1:
                f.write("\t\t\t\t.ptr = (void *){},\n".format(d.ptr))
            else:
                f.write("\t\t\t\t.ptr = (void *){}[{}],\n".format(d.ptr, n-1))

            f.write("\t\t\t\t.len = {}\n".format(d.len))
            f.write("\t\t\t}\n")

            f.write("\t\t}}{}\n".format("," if i != len(c.authenticated_data) - 1 else ""))

        f.write("\t}\n")

    f.write("};\n\n")
    if c.ifdef != "":
        f.write("#endif /* {} */\n\n".format(c.ifdef))

def rawImgToCert(i, certs):
    newCert = cert(i.img_name)
    newCert.img_id = i.img_id
    newCert.img_type = i.img_type
    newCert.parent = i.parent
    newCert.img_auth_methods = i.img_auth_methods
    newCert.ifdef = i.ifdef

    certs.append(newCert)
    return newCert

def generateBuf(certs, f):
    buffers = set()
    for c in certs:
        for d in c.authenticated_data:
            buffers.add(d.ptr)
            
    for buf in buffers:
        if "sp_pkg_hash_buf" in buf:
            f.write("static unsigned char {}[MAX_SP_IDS][HASH_DER_LEN];\n".format(buf))
        elif "pk" in buf:
            f.write("static unsigned char {}[PK_DER_LEN];\n".format(buf))
        else:
            f.write("static unsigned char {}[HASH_DER_LEN];\n".format(buf))

    f.write("\n")

def generateInclude(f):
    f.write("#include <stddef.h>\n")
    f.write("#include <mbedtls/version.h>\n")
    f.write("#include <common/tbbr/cot_def.h>\n")
    f.write("#include <drivers/auth/auth_mod.h>\n")
    f.write("#include <tools_share/cca_oid.h>\n")
    f.write("#include <platform_def.h>\n\n")

def generateLiscence(f):
    license = '''/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
'''
    f.write(license)
    f.write("\n")

def generateParam(certs, ctrs, pks, f):

    f.write("static auth_param_type_desc_t subject_pk = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_PUB_KEY, 0);\n")
    f.write("static auth_param_type_desc_t sig = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_SIG, 0);\n")
    f.write("static auth_param_type_desc_t sig_alg = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_SIG_ALG, 0);\n")
    f.write("static auth_param_type_desc_t raw_data = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_RAW_DATA, 0);\n")
    f.write("\n")

    for c in certs:
        if c.ifdef != "" and len(c.authenticated_data) != 0:
            f.write("#if defined({})\n".format(c.ifdef))
        
        for d in c.authenticated_data:
            if "pk" in d.type_desc:
                f.write("static auth_param_type_desc_t {} = "\
                        "AUTH_PARAM_TYPE_DESC(AUTH_PARAM_PUB_KEY, {});\n".format(d.type_desc, d.oid))
            elif "hash" in d.type_desc:
                f.write("static auth_param_type_desc_t {} = "\
                        "AUTH_PARAM_TYPE_DESC(AUTH_PARAM_HASH, {});\n".format(d.type_desc, d.oid))
            elif "ctr" in d.type_desc:
                f.write("static auth_param_type_desc_t {} = "\
                        "AUTH_PARAM_TYPE_DESC(AUTH_PARAM_NV_CTR, {});\n".format(d.type_desc, d.oid))

        if c.ifdef != "" and len(c.authenticated_data) != 0:
            f.write("#endif /* {} */\n".format(c.ifdef))

    f.write("\n")

    for c in ctrs:
        f.write("static auth_param_type_desc_t {} = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_NV_CTR, {});\n".format(c.name, c.oid))

    for p in pks:
        f.write("static auth_param_type_desc_t {} = AUTH_PARAM_TYPE_DESC(AUTH_PARAM_PUB_KEY, {});\n".format(p.name, p.oid))

    f.write("\n")

def generateCotDef(certs, f):
    f.write("static const auth_img_desc_t * const cot_desc[] = {\n")
    for i, c in enumerate(certs):
        if c.ifdef != "":
            f.write("#if defined({})\n".format(c.ifdef))
        
        f.write("\t[{}]	=	&{}{}\n".format(c.cert_name.upper() + "_ID", c.cert_name, "," if i != len(certs) - 1 else ""))
        
        if c.ifdef != "":
            f.write("#endif\n")

    f.write("}\n\n")
    f.write("REGISTER_COT(cot_desc);\n")

def generateCot(images, certs, ctrs, pks, outputfileName):
    f = open(outputfileName, 'a')

    generateLiscence(f)
    generateInclude(f)
    generateBuf(certs, f)

    for i in images:
        c = rawImgToCert(i, certs)
    
    generateParam(certs, ctrs, pks, f)

    for c in certs:
        generateCert(c, f)

    generateCotDef(certs, f)

    f.close()
    return

def main(): 
    filename = open(sys.argv[1])
    outputfileName = sys.argv[2]

    braces = []

    allImages = []
    certs = []
    pks = []
    ctrs = []

    regex = re.compile(r'([\w]+) *: *([\w]+)')
    pkregex = re.compile(r'[\w]_keys *{')
    brace = re.compile(r' *{ *')

    for line in filename:
        if "images" in line:
            braces.append("{")
            allImages = images(filename, braces)
            continue
        
        if "manifests" in line:
            braces.append("{")
            certs = manifest(filename, braces)
            continue
        
        match = regex.search(line)
        if match != None:
            word1, word2 = match.groups()
            if "counter" in word2:
                ctrs = Ctrs(filename)
            continue

        match = pkregex.search(line)
        if match != None:
            pks = PKs(filename)
            continue

    generateCot(allImages, certs, ctrs, pks, outputfileName)
  
if __name__=="__main__": 
    if (len(sys.argv) < 3):
        print("usage: python3 " + sys.argv[0] + " [dtsi file path] [output c file path]")
        exit()
    main() 