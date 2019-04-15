# run script like this: >>> python3.6 email_config_health_checker.py esa_config.xml

import xml.etree.ElementTree as ET
import sys

def debug(message):
    print(message)

# function to open XML file and get the root
def get_root_xml():
    # Grab file name from argument that is passed a long with script execution. 
    # Download file from your ESA and put in same directory as this script
    file_name = sys.argv[1]

    # open the file for reading
    global XML_File
    XML_File = open(file_name, 'r')

    if XML_File:
        # user feed back
        debug("XML file {} successfully opened!\n".format(file_name)) 
        
        # parse XML file
        tree = ET.parse(XML_File)

        global root
        root = tree.getroot()

    else:
        debug("XML File not Found, make sure to pass along file name as argument when calling script.\n")

# hacky function that grabs the licenses in the comments of the XML and fills a dictionary with it.
def get_licenses():
    global licenses_dict
    licenses_dict = {
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

    for line in XML_File:
        if "Feature" in line:
            if "External Threat Feeds" in line:
                licenses_dict['ETF'] = 1
            elif "File Reputation" in line:
                licenses_dict['AMP'] = 1
            elif "File Analysis" in line:
                licenses_dict['TG'] = 1
            elif "IronPort Anti-Spam" in line:
                licenses_dict['CASE'] = 1
            elif "Outbreak Filters" in line:
                licenses_dict['OF'] = 1
            elif "Cloudmark SP" in line:
                licenses_dict['CSP'] = 1
            elif "Bounce Verification" in line:
                licenses_dict['BV'] = 1
            elif "Incoming Mail Handling" in line:
                licenses_dict['IMH'] = 1
            elif "Intelligent Multi-Scan" in line:
                licenses_dict['IMS'] = 1
            elif "IronPort Email Encryption" in line:
                licenses_dict['IEE'] = 1
            elif "Data Loss Prevention" in line:
                licenses_dict['DLP'] = 1
            elif "Sophos" in line:
                licenses_dict['SOP'] = 1
            elif "McAfee" in line:
                licenses_dict['MCA'] = 1

# function that does a lookup for the XML tag and returns the value (text)
def xml_lookup(xml_tag):
    xml_value = root.iter(xml_tag).text
    return xml_value

def check_rules():
    if xml_lookup('case_enabled') == 1:  
        debug("You CASE Anti-Spam engine is correctly enabled\n")
    else:
        debug("You CASE Anti-Spam engine is not enabled\n")

    if xml_lookup('ims_enabled') == 1:
        debug("You IMS engine is correctly enabled\n")
    else:
        debug("You IMS engine is not enabled\n")

    if xml_lookup('rep_enabled') == 1 and licenses_dict('AMP') == 1:
        debug("You Advanced Malware Protection engine is correctly enabled\n")
    else:
        debug("You Advanced Malware Protection engine is not enabled\n")

if __name__ == "__main__":
    get_root_xml()
    get_licenses()
    check_rules()
