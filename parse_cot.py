from sys import exit

import re
import sys

class authMethod:
    def __init__(self):
        self.type = ""
        self.param = ""
        self.paramKey = []
        self.paramValue = []

class authData:
    def __init__(self, type_desc):
        self.type_desc = type_desc
        self.ptr = ""
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

    def printInfo(self):
        print("============== image ==============")
        print("image id:", self.image_id)
        print("parent:", self.parent)
        print("hash:", self.hash)

class cert:
    def __init__(self, certName):
        self.certName = certName
        self.img_id = ""
        self.img_type = ""
        self.parent = ""
        self.signing_key = ""
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
        print("signing key:", self.signing_key)
        print("antirollback:", self.antirollback_counter)
        print("authenticated data:")
        for d in self.authenticated_data:
            d.printInfo()

def removeNumber(s):
    result = ''.join([i for i in s if not i.isdigit()])
    return result

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
            thisCert.parent = None
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
    

def main(): 
    filename = open(sys.argv[1])
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

    for c in certs:
        c.printInfo()
    for i in allImages:
        i.printInfo()
  
if __name__=="__main__": 
    main() 