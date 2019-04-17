#!/usr/bin/python3

# run script like this: >>> python3.6 email_config_health_checker.py esa_config.xml

import xml.etree.ElementTree as ET
import sys
import json
import re


def debug(message):
    print(message)

# class for email health check 
class EHC:
    def __init__(self,filename,ourdomain=""):
        self.ourdomain = ourdomain
        self.XML_File = open(filename,'r')
        if self.XML_File:
            debug("XML file {} successfully opened!\n".format(filename))             
            self.tree = ET.parse(filename)
            debug("tree is {}".format(self.tree))            
            self.root = self.tree.getroot()
            debug("Root is {}".format(self.root))
            debug("printing children")
            for child in self.root:
                debug("child tag {} child atrib {}".format(child.tag,child.attrib))

            self.remarks = []
        else:
            debug("Could not open file {}".format(filename))

            
    def get_licenses(self):
        self.licenses_dict = {
            'ETF': 0,
            'AMP': 0,
            'TG': 0,
            'CASE': 0,
            'OF': 0,
            'CSP': 0,
            'BV': 0,
            'IMH': 0,
            'IMS': 0,
            'IEE': 0,
            'DLP': 0,
            'SOP': 0,
            'MCA': 0
        }

        for line in self.XML_File:
            if "Feature" in line:
                if "External Threat Feeds" in line:
                    self.licenses_dict['ETF'] = 1
                elif "File Reputation" in line:
                    self.licenses_dict['AMP'] = 1
                elif "File Analysis" in line:
                    self.licenses_dict['TG'] = 1
                elif "IronPort Anti-Spam" in line:
                    self.licenses_dict['CASE'] = 1
                elif "Outbreak Filters" in line:
                    self.licenses_dict['OF'] = 1
                elif "Cloudmark SP" in line:
                    self.licenses_dict['CSP'] = 1
                elif "Bounce Verification" in line:
                    self.licenses_dict['BV'] = 1
                elif "Incoming Mail Handling" in line:
                    self.licenses_dict['IMH'] = 1
                elif "Intelligent Multi-Scan" in line:
                    self.licenses_dict['IMS'] = 1
                elif "IronPort Email Encryption" in line:
                    self.licenses_dict['IEE'] = 1
                elif "Data Loss Prevention" in line:
                    self.licenses_dict['DLP'] = 1
                elif "Sophos" in line:
                    self.licenses_dict['SOP'] = 1
                elif "McAfee" in line:
                    self.licenses_dict['MCA'] = 1
        debug(json.dumps(self.licenses_dict,indent=4,sort_keys=True))

        
    def xml_get_text_in_tag(self,xml_tag):

        found_items = 0
        for item in self.root.iter(xml_tag):
             found_items = found_items +1
             text = item.text
        if found_items == 1:
            return text
        else:
            debug("did not find exactly one of tag {}, found {}".format(xml_tag,str(found_items)))
             
    def add_remark_warning(self,txt):
        remark = {"level":"warning","text":txt}
        self.remarks.append(remark)

    def add_remark_ok(self,txt):
        remark = {"level":"ok","text":txt}
        self.remarks.append(remark)

    def print_remarks(self):
        for r in self.remarks:
            print(r["level"] + r["text"])
            
    def check_rules(self):

        rules_enabled = [
            { 'name':'Checking if CASE Anti-SPAM Enabled', 'text': 'case_enabled', 'value':'1','license':None },
            { 'name':'Checking if Intelligent Multi-Scan Enabled', 'text': 'ims_enabled', 'value':'1','license':None },
            { 'name':'Checking if File Reputation Enabled', 'text': 'rep_enabled', 'value':'1','license':None },
            { 'name':'Checking if URL Scanning Enabled', 'text': 'urlscanning_enabled', 'value':'1','license':None },
            { 'name':'Checking if Graymail Detection Enabled', 'text': 'graymail_detection_enabled', 'value':'1','license':None },
            { 'name':'Checking if Domain Reputation Enabled', 'text': 'domain_rep_enabled', 'value':'1','license':None },                        
            
        ]
        rules_values = [
            { 'name':'Checking SPAM threshold for always scan', 'text': 'case_advisory_scan_size', 'minvalue':'1048176','maxvalue':'1048176','license':None },
            { 'name':'Checking SPAM threshold for never scan', 'text': 'case_max_message_size', 'minvalue':'2097152','maxvalue':'2097152','license':None },
        ]
        for r in rules_enabled:
            if self.xml_get_text_in_tag(r["text"]) == r["value"]:
                self.add_remark_ok(r["name"])
            else:
                self.add_remark_warning(r["name"])

        for r in rules_values:
            config_value = int(self.xml_get_text_in_tag(r["text"]))
            if config_value >= int(r["minvalue"]) and config_value <= int(r["maxvalue"]):
                self.add_remark_ok(r["name"])
            else:
                self.add_remark_warning(r["name"] + " " + str(config_value))                
                                                         

    def xml_get_hat_incoming(self):
## ugly assumes first hat is hat for incoming
        found_items = 0
        for item in self.root.iter("hat"):
             found_items = found_items +1
             found_hat = item.text
             return found_hat

    def print_result(self):
        print(json.dumps(self.remarks,indent=4,sort_keys=True))
        
    def check_hat(self):
        hat = self.xml_get_hat_incoming()
        debug("start hat")
        debug(hat)
        debug("end hat")


        x = None

        lines = hat.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            ### Check WHITELIST, that not too many IPs are defined
            x = re.search("^WHITELIST:",line)
            if x:
                debug("match WHITELIST")
                debug(x.string)
                num_of_IPs_in_whitelist = 0
                grabbed_whitelist = False
                while grabbed_whitelist == False:
                    i = i + 1
                    line1 = lines[i]
                    y = re.search("\$",line1)
                    if y:
# end of whitelist
                        break
                    else:
                        newip = line1
                        num_of_IPs_in_whitelist = num_of_IPs_in_whitelist + 1
                        debug("New IP found in whitelist {}".format(newip))
                if num_of_IPs_in_whitelist > 10:
                    self.add_remark_warning("Lots of IPs in WHITELIST {}".format(str(num_of_IPs_in_whitelist)))
                else:
                    self.add_remark_ok("Reasonable number of IPs in  WHITELIST {}".format(str(num_of_IPs_in_whitelist)))

            #
            #  Check that BLACKLIST SRBRS score has not been changed and that policy is BLOCKED!
            #
            x = re.search("^BLACKLIST:",line)
            if x:
                debug("match BLACKLIST")
                debug(x.string)
                i = i+1
                line1 = lines[i]
                debug("blacklist is " + line1)
                line1 = line1.replace("sbrs[","")
                line1 = line1.replace("]","")
                (low,high) = line1.split(':')
                low = low.strip()
                high = high.strip()
                debug(low)
                debug(high)
                blacklist_ok = True
                if (float(low) > -10):
                    self.add_remark_warning("Too lenient blacklist! Lower end is {}".format(low))
                    blacklist_ok = False
                if (float(high) > -3):
                    self.add_remark_warning("Too lenient blacklist! Higher End  is {}".format(high))
                    blacklist_ok = False                        
                if (float(high) < -3):
                    self.add_remark_warning("Too harsh blacklist! Higher End  is {}".format(high))
                    blacklist_ok = False
                i = i+1
                line1 = lines[i]
                y = re.search("\$BLOCKED",line1)
                if not y:
                    self.add_remark_warning("Blacklist is not Blocking!! {}".format(line1))
                    blacklist_ok = False
                if blacklist_ok:
                    self.add_remark_ok("Blacklist is ok, low {} high {}, and blocking".format(low,high))
            #
            #  Check that SUSPECTLIST SRBRS score has not been changed and that policy is THROTTLED!
            #  check that SBRS score none -> throttled...
            x = re.search("^SUSPECTLIST:",line)
            if x:
                debug("match SUSPECTLIST")
                debug(x.string)
                i = i+1
                line1 = lines[i]
                debug("suspectlist is " + line1)
                line1 = line1.replace("sbrs[","")
                line1 = line1.replace("]","")
                (low,high) = line1.split(':')
                low = low.strip()
                high = high.strip()
                debug(low)
                debug(high)
                suspectlist_ok = True
                if (float(low) != -3.0):
                    self.add_remark_warning("Changed defaults for Suspect List! Lower end is {}".format(low))
                    suspectlist_ok = False
                if (float(high) != -1.0):
                    self.add_remark_warning("Changed defaults for Suspect List! Higher End  is {}".format(high))
                    suspectlist_ok = False                        
                i = i+1
                line1 = lines[i]
                if "sbrs[none]" in line1:
                    self.add_remark_ok("Suspectlist contains domains with no reputation sbrs[none] {}".format(line1))
                    i = i+1
                    line1 = lines[i]
                else:
                    suspectlist_ok = False
                    self.add_remark_warning("Suspectlist should contain domains with no reputation sbrs[none] {}".format(line1))
                y = re.search("\$THROTTLED",line1)
                if not y:
                    self.add_remark_warning("Suspectlist should be throttled {}".format(line1))
                    suspectlist_ok = False
                if suspectlist_ok:
                    self.add_remark_ok("Suspectlist is ok, low {} high {}, including none-reputation and throttling".format(low,high))
            #                
            
                    
            i = i + 1

            
if __name__ == "__main__":

    filename = sys.argv[1]
    debug("Filename is {}".format(filename))
    ehc = EHC(filename)
    ehc.get_licenses()
    ehc.check_rules()
    ehc.check_hat()
    ehc.print_result()
    
