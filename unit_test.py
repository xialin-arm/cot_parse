from sys import exit

import re
import sys
import math

def removeNumber(s):
    result = ''.join([i for i in s if not i.isdigit()])
    return result

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
    
    def init_sign(self, keyname):
        self.type = "AUTH_METHOD_SIG"
        self.param = "sig"
        self.paramKey = ["pk", "sig", "alg", "data"]
        self.paramValue = [keyname, "sig", "sig_alg", "raw_data"]

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

    def compare(self, method, certName="", diff=False):
        if self.type != method.type:
            if not diff:
                print("--------- " + certName + " ------------")
                diff = True
            print("different method type: " + self.type + "," + method.type)
        if self.param != method.param:
            if not diff:
                print("--------- " + certName + " ------------")
                diff = True
            print("different param name: " + self.param + "," + method.param)
        for i in range(len(self.paramKey)):
            if self.paramKey[i] != method.paramKey[i]:
                if not diff:
                    print("--------- " + certName + " ------------")
                    diff = True
                print("different param key: " + self.paramKey[i] + "," + method.paramKey[i])
            if self.paramValue[i] != method.paramValue[i]:
                if not diff:
                    print("--------- " + certName + " ------------")
                    diff = True
                print("different paramValue: " + self.paramValue[i] + "," + method.paramValue[i])

        return diff

class authData:
    def __init__(self):
        self.type_desc = ""
        self.oid = ""
        self.len = ""
        self.ptr = ""

    # def __init__(self, type_desc):
    #     self.type_desc = type_desc
    #     if "sp_pkg" in type_desc:
    #         type_desc = removeNumber(type_desc)
    #     self.ptr = type_desc + "_buf"
    #     if "hash" in type_desc:
    #         self.len = "(unsigned int)HASH_DER_LEN"
    #     elif "pk" in type_desc:
    #         self.len = "(unsigned int)PK_DER_LEN"
    #     self.oid = ""

    def printInfo(self):
        print("--------------- data ----------------")
        print("type_desc:", self.type_desc)
        print("oid:", self.oid)
        print("ptr:", self.ptr)
        print("len:", self.len)
    
    def compare(self, data, certname="", diff=False):
        if self.type_desc != data.type_desc:
            if not diff:
                print("--------- " + certname + " ------------")
                diff = True
            print("different type_desc " + self.type_desc + "," + data.type_desc)
        if self.ptr != data.ptr:
            if not diff:
                print("--------- " + certname + " ------------")
                diff = True
            print("different ptr " + self.ptr + "," + data.ptr)
        if self.len != data.len:
            if not diff:
                print("--------- " + certname + " ------------")
                diff = True
            print("different len " + self.len + data.len)

        return diff

class cert:
    def __init__(self, certName):
        self.cert_name = certName
        self.img_id = ""
        self.img_type = "IMG_CERT"
        self.parent = ""
        self.ifdef = ""
        self.signing_key = ""
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

    def compare(self, cert):
        if self.cert_name != cert.cert_name:
            print("comparing different certs: " + self.cert_name + "," + cert.cert_name)
            return
        
        isdiff = False

        if self.img_id != cert.img_id:
            if not isdiff:
                print("--------- " + self.cert_name + " ------------")
                isdiff = True
            print("different img_id: " + self.img_id + "," + cert.img_id)
        if self.img_type != cert.img_type:
            if not isdiff:
                print("--------- " + self.cert_name + " ------------")
                isdiff = True
            print("different img_type: " + self.img_type + "," + cert.img_type)
        if self.parent != cert.parent:
            if not isdiff:
                print("--------- " + self.cert_name + " ------------")
                isdiff = True
            print("different parent: " + self.parent + "," + cert.parent)
        if self.signing_key != cert.signing_key:
            if not isdiff:
                print("--------- " + self.cert_name + " ------------")
                isdiff = True
            print("different signing_key: " + self.signing_key + "," + cert.signing_key)

        n = len(self.authenticated_data)
        if len(self.authenticated_data) != len(cert.authenticated_data):
            print("different authenticated_data length")
            n = min(len(self.authenticated_data), len(cert.authenticated_data))
        for i in range(n):
            if i < len(cert.authenticated_data):
                isdiff = self.authenticated_data[i].compare(cert.authenticated_data[i], self.cert_name, isdiff)

        n = len(self.img_auth_methods)
        if len(self.img_auth_methods) != len(self.img_auth_methods):
            print("different auth method")
            n = min(len(self.img_auth_methods), len(self.img_auth_methods))
        for i in range(n):
            if i < len(cert.img_auth_methods):
                isdiff = self.img_auth_methods[i].compare(cert.img_auth_methods[i], self.cert_name, isdiff)

        if isdiff:
            print("---------------------------------------")

        return


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

def extract_method_param(filename, method):
    methodparaReg = re.compile(r'.param.([\w]+) *= *{')
    keyvalue = re.compile(r'.([\w]+) = &([\w]*)')
    stack = ["{"]

    for line in filename:
        match = methodparaReg.search(line)
        if match != None:
            method.param = match.groups()[0]
            continue

        match = keyvalue.search(line)
        if match != None:
            key, value = match.groups()
            method.paramKey.append(key)
            method.paramValue.append(value)
            continue
        
        if parseBraces(line, stack):
            return 

def extract_method(filename, cert):
    methodtypeReg = re.compile(r'.type *= *([\w]+),')
    method = authMethod()
    stack = ["{"]

    for line in filename:
        match = methodtypeReg.search(line)
        if match != None:
            method.type = match.groups()[0]
            extract_method_param(filename, method)

        else:
            if parseBraces(line, stack):
                cert.img_auth_methods.append(method)
                return
    

def extract_methods(filename, cert):
    idxReg = re.compile(r'\[([\d]+)\] *= *{')
    stack = ["{"]

    for line in filename:
        match = idxReg.search(line)
        if match != None:
            extract_method(filename, cert)

        else:
            if parseBraces(line, stack):
                return

def extract_data_param(filename, data):
    ptrReg = re.compile(r'.ptr *=')
    lenReg = re.compile(r'.len *=')
    stack = ["{"]

    for line in filename:
        match = ptrReg.search(line)
        if match != None:
            data.ptr = match.groups()[0]
            continue

        match = lenReg.search(line)
        if match != None:
            data.len = match.groups()[0]
            continue
        
        if parseBraces(line, stack):
            return 


def extract_data(filename, cert):
    methodtypeReg = re.compile(r'.type_desc *= *([\w]+),')
    data = authData()
    stack = ["{"]

    for line in filename:
        match = methodtypeReg.search(line)
        if match != None:
            data.type_desc = match.groups()[0]

        else:
            if parseBraces(line, stack):
                cert.authenticated_data.append(data)
                return

    return

def extract_allData(filename, cert):
    idxReg = re.compile(r'\[([\d]+)\] *= *{')
    stack = ["{"]

    for line in filename:
        match = idxReg.search(line)
        if match != None:
            extract_data(filename, cert)
        
        else:
            if parseBraces(line, stack):
                return

    return

def extract_cert(fileName, certname, ifdefFlag=False, ifdefTag=""):
    imgidReg = re.compile(r'.img_id *= *([\w]+),')
    imgTypeReg = re.compile(r'.img_type *= *([\w]+),')
    imgParentReg = re.compile(r'.parent *= *&([+w]+),')
    imgMethodReg = re.compile(r'.img_auth_methods')
    imgDataReg = re.compile(r'.authenticated_data')

    thisCert = cert(certname)
    if ifdefFlag:
        thisCert.ifdef = ifdefTag

    stack = ["{"]

    for line in fileName:
        match = imgidReg.search(line)
        if match != None:
            thisCert.img_id = match.groups()[0]
            continue

        match = imgTypeReg.search(line)
        if match != None:
            thisCert.img_type = match.groups()[0]
            continue

        match = imgParentReg.search(line)
        if match != None:
            thisCert.parent = match.groups()[0]
            continue

        match = imgMethodReg.search(line)
        if match != None:
            extract_methods(fileName, thisCert)
            continue

        match = imgDataReg.search(line)
        if match != None:
            extract_allData(fileName, thisCert)
            continue

        if parseBraces(line, stack):
            return thisCert

def extract_certs(fileName, firstCert):
    certs = {firstCert:0}
    certDetail = []
    certDetail.append(extract_cert(fileName, firstCert))

    ifdefregex = re.compile(r'#ifdef *([\w]+)')
    ifdefend = "#endif"

    ifdefFlag = False
    ifdefTag = ""

    certReg = re.compile(r'static const auth_img_desc_t ([\w]+) *= *{')
    cotReg = re.compile(r'static const auth_img_desc_t \* const cot_desc\[\]')
    pkgReg1 = re.compile(r'DEFINE_SIP_SP_PKG\(([\d]+)\);')
    pkgReg2 = re.compile(r'DEFINE_PLAT_SP_PKG\(([\d]+)\);')

    for line in fileName:
        match = certReg.search(line)
        if match != None:
            certs[match.groups()[0]] = len(certDetail)
            certDetail.append(extract_cert(fileName, match.groups()[0], ifdefFlag, ifdefTag))
            continue

        match = ifdefregex.search(line)
        if match != None:
            ifdefFlag = True
            ifdefTag = match.groups()[0]
        
        if ifdefend in line:
            ifdefFlag = False
            ifdefTag = ""

        match = pkgReg1.search(line)
        if match != None:
            name = "sp_pkg" + match.groups()[0]
            if name not in certs:
                certs[name] = -1
            continue

        match = pkgReg2.search(line)
        if match != None:
            name = "sp_pkg" + match.groups()[0]
            if name not in certs:
                certs[name] = -1
            continue
        
        match = cotReg.search(line)
        if match != None:
            return certs, certDetail

    return certs, certDetail

def extract_cot(fileName):
    cotReg = re.compile(r'\[([\w]+)\][\t ]*=[\t ]*&([\w]+)')
    cotheadReg = re.compile(r'static const auth_img_desc_t \* const cot_desc\[\]')
    id = []
    value = []

    for line in fileName:
        match = cotReg.search(line)
        if match != None:
            word1, word2 = match.groups()
            id.append(word1)
            value.append(word2)
        
        match = cotheadReg.search(line)
        if match != None:
            id = []
            value = []

    return id, value

def main():
    ref = open(sys.argv[1])
    test = open(sys.argv[2])

    refCharBuf, refCharBufLen, refParam, refFirstCert = extract_param(ref)
    testCharBuf, testCharBuflen, testParam, testfirstCert = extract_param(test)

    refCerts, refcertDetail = extract_certs(ref, refFirstCert)
    testCerts, testcertDetail = extract_certs(test, testfirstCert)
    
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
    certBL1 = []

    for i in refCerts.keys():
        if i not in testCerts.keys():
            refidx = refCerts[i]
            if refidx != -1:
                ref = refcertDetail[refidx]
                if ref.ifdef != 'IMAGE_BL1':
                    certMissing.append(i)
                else:
                    certBL1.append(ref.cert_name)
        
        else:
           refidx = refCerts[i]
           testidx = testCerts[i]
           if refidx != -1 and testidx != -1:
            ref = refcertDetail[refidx]
            test = testcertDetail[testidx]
            ref.compare(test)
    
    for i in testCerts.keys():
        if i not in refCerts.keys():
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
        if i not in testCotKey and i[:-3].lower() not in certBL1:
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

    print("image belongs to BL1:")
    print(certBL1)

    return

if __name__=="__main__": 
    if (len(sys.argv) < 3):
        print("usage: python3 " + sys.argv[0] + " [reference file path] [output c file path]")
        exit()
    main() 