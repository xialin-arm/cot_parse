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
    def __init__(self):
        self.type_desc = ""
        self.ptr = ""
        self.len = ""

class cert:
    def __init__(self, certName):
        self.certName = certName
        self.img_id = ""
        self.img_type = ""
        self.parent = ""
        self.img_auth_methods = []
        self.authenticated_data = []

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

def extractCert(filename):
    stack = ["{"]

    for line in filename:

        if parseBraces(line, stack):
            print("cert done")
            return
        

def manifest(filename, braces):
    reg = re.compile(r'([\w]+) *: *([\w]+)')

    for line in filename:
        match = reg.search(line)

        if match != None:
            word1, word2 = match.groups()
            extractCert(filename)

        else:
            if parseBraces(line, braces):
                print("manifests done")
                return 
        

def images(filename, braces):
    reg = re.compile(r'([\w]+) *{')

    for line in filename:
        match = reg.search(line)
        
        if match != None:
            word = match.groups()[0]
            print(word)

        if parseBraces(line, braces):
            print("images done")
            return
    

def main(): 
    filename = open(sys.argv[1])
    braces = []
    for line in filename:
        if "images" in line:
            braces.append("{")
            images(filename, braces)
        elif "manifests" in line:
            braces.append("{")
            manifest(filename, braces)
  
if __name__=="__main__": 
    main() 