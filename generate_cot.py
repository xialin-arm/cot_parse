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
        self.ptr = removeNumber(type_desc) + "_buf"
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
        self.imageName = imageName
        self.image_id = ""
        self.parent = ""
        self.hash = ""
        self.image_type = "IMG_RAW"

    def printInfo(self):
        print("============== image ==============")
        print("image name:", self.imageName)
        print("image id:", self.image_id)
        print("parent:", self.parent)
        print("hash:", self.hash)

class cert:
    def __init__(self, certName):
        self.certName = certName
        self.img_id = ""
        self.img_type = "IMG_CERT"
        self.parent = ""
        # self.signing_key = ""
        self.antirollback_counter = ""
        self.img_auth_methods_name = "(const auth_method_desc_t[AUTH_METHOD_NUM])"
        self.img_auth_methods = []
        self.authenticated_data_name = "(const auth_param_desc_t[COT_MAX_VERIFIED_PARAMS])"
        self.authenticated_data = []

    def printInfo(self):
        print("===================== cert ======================")
        print("cert:", self.certName)
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


def extractCert(filename, certName):
    stack = ["{"]
    thisCert = cert(certName)

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

    for line in filename:
        match = reg.search(line)

        if match != None:
            word1, word2 = match.groups()
            certs.append(extractCert(filename, word2))

        else:
            if parseBraces(line, braces):
                #print("manifests done")
                return certs
        
def extractImage(filename, imageName):
    stack = ["{"]
    thisImage = image(imageName)

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
            thisImage.image_id = match.groups()[0]
            continue

        match = hashregex.search(line)
        if match != None:
            thisImage.hash = match.groups()[0]
            continue

        if parseBraces(line, stack):
            return thisImage

def images(filename, braces):
    allImages = []

    reg = re.compile(r'([\w]+) *{')

    for line in filename:
        match = reg.search(line)
        
        if match != None:
            word = match.groups()[0]
            #print(word)
            allImages.append(extractImage(filename, word))

        else:
            if parseBraces(line, braces):
                #print("images done")
                return allImages
    
def generateCert(c, f):
    f.write("static const auth_img_desc_t {} = {{\n".format(c.certName))
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
            if n == -1:
                f.write("\t\t\t\t.ptr = (void *){},\n".format(d.ptr))
            else:
                f.write("\t\t\t\t.ptr = (void *){}[{}],\n".format(d.ptr, n-1))

            f.write("\t\t\t\t.len = {}\n".format(d.len))
            f.write("\t\t\t}\n")

            f.write("\t\t}}{}\n".format("," if i != len(c.authenticated_data) - 1 else ""))

        f.write("\t}\n")

    f.write("};\n\n")

def rawImgToCert(i, certs):
    newCert = cert(i.imageName)
    newCert.img_id = i.image_id
    newCert.img_type = i.image_type
    newCert.parent = i.parent

    m = authMethod()
    m.init_hash(i.hash)
    newCert.img_auth_methods.append(m)

    certs.append(newCert)
    return newCert

def generateCot(images, certs, outputfileName):
    f = open(outputfileName, 'a')

    f.write("#include <stddef.h>\n")
    f.write("#include <mbedtls/version.h>\n")
    f.write("#include <common/tbbr/cot_def.h>\n")
    f.write("#include <drivers/auth/auth_mod.h>\n")
    f.write("#include <tools_share/cca_oid.h>\n")
    f.write("#include <platform_def.h>\n\n")

    for c in certs:
        generateCert(c, f)

    for i in images:
        c = rawImgToCert(i, certs)
        generateCert(c, f)

    f.close()
    return

def main(): 
    filename = open(sys.argv[1])
    outputfileName = sys.argv[2]

    braces = []

    allImages = []
    certs = []

    for line in filename:
        if "images" in line:
            braces.append("{")
            allImages = images(filename, braces)
        elif "manifests" in line:
            braces.append("{")
            certs = manifest(filename, braces)

    generateCot(allImages, certs, outputfileName)
  
if __name__=="__main__": 
    if (len(sys.argv) < 3):
        print("usage: python3 " + sys.argv[0] + " [dtsi file path] [output c file path]")
        exit()
    main() 