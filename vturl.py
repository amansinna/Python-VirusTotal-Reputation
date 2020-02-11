import requests
import sys
import csv
import json
import time
import urllib.request

if len(sys.argv) != 2:
        print("Usage: url_lookup.py [input file]")
        sys.exit()

url_list = sys.argv[1]
api_key = "29932dea25c8bf9c9dc1b712c746eba6f3617d697e1d4372e31b1290e48d8380"

def vt_url_lookup(url, tries): #tries = number of recursions allowed (20 sec wait in between)
        if tries == 0:
                return {"valid":False, "error_msg":"Max tries exceeded"}
        tries -= 1
        api_key = "29932dea25c8bf9c9dc1b712c746eba6f3617d697e1d4372e31b1290e48d8380"
        params = {"apikey":api_key, "resource":url, "scan":"1", "allinfo":"true"}
        try:
                response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        except Exception as e:
                return {"valid":False, "error_msg" : "Unexpected Error: " + str(e)}
        else:
                if response.status_code != 200:
                        return {"valid":False, "error_msg" : "Request Error - HTTP " + str(response.status_code)}
                else:
                        rjson = response.json()
                        try:
                                if "scan information embedded in this object" not in rjson['verbose_msg']:
                                        print("[!]Waiting 20 seconds for VT to scan " + url + "[!]")
                                        time.sleep(20)
                                        response = None #clear before recursive call
                                        return vt_url_lookup(url, tries)
                                elif rjson['response_code'] == 1:
                                        return {"valid":True, "response":rjson}
                                else:
                                        return "API Error: response_code: " + str(rjson['response_code'])
                        except Exception as e:
                                return {"valid":False, "error_msg" : "Unexpected Error: " + str(e)}


with open('url_results_' + time.strftime("%Y%m%d_%H%M") + '.csv', 'w', newline ='') as csvfile:
        cwriter = csv.writer(csvfile, dialect='excel', delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        cwriter.writerow(['URL', 'Resolved IP', 'Scan Date', 'Errors', 'Categories', 'VT Score', 'Priority Engine Score',  \
        'Forcepoint ThreatSeeker category', 'Forcepoint ThreatSeeker', 'Malwarebytes hpHosts', 'ESET', 'Fortinet', 'Kaspersky', \
        'Trustwave', 'AlienVault', 'BitDefender', 'Google Safebrowsing', 'Sophos AV', 'Sucuri SiteCheck', \
        'Domain Name', 'Registrar WHOIS Server', 'Registrar URL', 'Registrar', 'Registrant Name', 'Registrant Organization', \
        'Registrant Country', 'Admin Name', 'Admin Organization', 'Admin Country', 'Tech Name', 'Tech Organization' , 'Tech Country', 'ASN', 'AS Owner', 'AS Country'])
        with open(url_list) as url_list:
                total=sum(1 for _ in url_list if _.rstrip())
                url_list.seek(0)
                index = 1
                for url_raw in url_list:
                        url = url_raw.rstrip()
                        if url:
                                print("Processing ({:d}/{:d}): {}".format(index, total, url))
                                index += 1
                                try:
                                        result = vt_url_lookup(url, 3)
                                        if result['valid']:
                                                
                                                #whois data lookup
                                                url2 = 'https://www.virustotal.com/vtapi/v2/domain/report'
                                                parameters = {'domain': url, 'apikey': api_key}
                                                response = urllib.request.urlopen('%s?%s' % (url2, urllib.parse.urlencode(parameters))).read()
                                                response_dict = json.loads(response)
                                                whoIs = response_dict.get("whois")
                                                whoisSplit = whoIs.split("\n") if whoIs != None else ""
                                                whoisDict = {}
                                                if whoIs != "":
                                                    for x in whoisSplit:
                                                        item = x.split(":")
                                                        whoisDict[item[0]] = item[1]

                                                Domain_Name = whoisDict.get("Domain Name") if whoisDict.get("Domain Name") else ""
                                                Registrar_WHOIS_Server = whoisDict.get("Registrar WHOIS Server") if whoisDict.get("Registrar WHOIS Server") else ""
                                                Registrar_URL = whoisDict.get("Registrar URL") if whoisDict.get("Registrar URL") else ""
                                                registrar = whoisDict.get("Registrar") if whoisDict.get("Registrar") else ""
                                                Registrant_Name = whoisDict.get("Registrant Name") if whoisDict.get("Registrant Name") else ""
                                                Registrant_Organization = whoisDict.get("Registrant Organization") if whoisDict.get("Registrant Organization") else ""
                                                country = whoisDict.get("Registrant Country") if whoisDict.get("Registrant Country") else ""
                                                Admin_Name = whoisDict.get("Admin Name") if whoisDict.get("Admin Name") else ""
                                                Admin_Organization = whoisDict.get("Admin Organization") if whoisDict.get("Admin Organization") else ""
                                                Admin_Country = whoisDict.get("Admin Country") if whoisDict.get("Admin Country") else ""
                                                Tech_Name = whoisDict.get("Tech Name") if whoisDict.get("Tech Name") else ""
                                                Tech_Organization = whoisDict.get("Tech Organization") if whoisDict.get("Tech Organization") else ""
                                                Tech_Country = whoisDict.get("Tech Country") if whoisDict.get("Tech Country") else ""

                                                #print(json.dumps(whoisDict, indent = 2))
                                                
                                                priorityCount = 0
                                                response = result['response']
                                                #print(json.dumps(result, indent = 2))
                                                resolved_IP = response.get('additional_info').get('resolution') if response.get('additional_info') else ""
                                                scan_date = response.get('scan_date')
                                                vt_score = (" " + str(response.get('positives')) + "/" + str(response.get('total'))) if response.get('total') else ""
                                                #print(response.get('positives'))
                                                print(vt_score)
                                                #mb_hph = response.get('scans').get('Malwarebytes hpHosts').get('result') if response.get('scans').get('Malwarebytes hpHosts') else ""
                                                fpts = response.get('additional_info').get('Forcepoint ThreatSeeker category') if response.get('additional_info') else ""
                                                cats = response.get('additional_info').get('categories') if response.get('additional_info') else ""
                                                #Priority Engines
                                                fpThreat = response.get('scans').get('Forcepoint ThreatSeeker').get('result') if response.get('scans').get('Forcepoint ThreatSeeker') else ""
                                                if response.get('scans').get('Forcepoint ThreatSeeker'):
                                                    if response.get('scans').get('Forcepoint ThreatSeeker').get('detected') == True:
                                                        priorityCount+=1
                                                        
                                                mbbr = response.get('scans').get('Malwarebytes hpHosts').get('result') if response.get('scans').get('Malwarebytes hpHosts') else ""
                                                if response.get('scans').get('Malwarebytes hpHosts'):
                                                    if response.get('scans').get('Malwarebytes hpHosts').get('detected') == True:
                                                        priorityCount+=1
                                                        
                                                ESET = response.get('scans').get('ESET').get('result') if response.get('scans').get('ESET') else ""
                                                if response.get('scans').get('ESET'):
                                                    if response.get('scans').get('ESET').get('detected') == True:
                                                        priorityCount+=1
                                                        
                                                Fortinet = response.get('scans').get('Fortinet').get('result') if response.get('scans').get('Fortinet') else ""
                                                if response.get('scans').get('Fortinet'):
                                                    if response.get('scans').get('Fortinet').get('detected') == True:
                                                        priorityCount+=1
                                                        
                                                Kaspersky = response.get('scans').get('Kaspersky').get('result') if response.get('scans').get('Kaspersky') else ""
                                                if response.get('scans').get('Kaspersky'):
                                                    if response.get('scans').get('Kaspersky').get('detected') == True:
                                                        priorityCount+=1
                                                        
                                                Trustwave = response.get('scans').get('Trustwave').get('result') if response.get('scans').get('Trustwave') else ""
                                                if response.get('scans').get('Trustwave'):
                                                    if response.get('scans').get('Trustwave').get('detected') == True:
                                                        priorityCount+=1
                                                        
                                                AlienVault = response.get('scans').get('AlienVault').get('result') if response.get('scans').get('AlienVault') else ""
                                                if response.get('scans').get('AlienVault'):
                                                    if response.get('scans').get('AlienVault').get('detected') == True:
                                                        priorityCount+=1
                                                        
                                                BitDefender = response.get('scans').get('BitDefender').get('result') if response.get('scans').get('BitDefender') else ""
                                                if response.get('scans').get('BitDefender'):
                                                    if response.get('scans').get('BitDefender').get('detected') == True:
                                                        priorityCount+=1
                                                        
                                                googleSafebrowsing = response.get('scans').get('Google Safebrowsing').get('result') if response.get('scans').get('Google Safebrowsing') else ""
                                                if response.get('scans').get('Google Safebrowsing'):
                                                    if response.get('scans').get('Google Safebrowsing').get('detected') == True:
                                                        priorityCount+=1
                                                        
                                                Sophos = response.get('scans').get('Sophos').get('result') if response.get('scans').get('Sophos') else ""
                                                if response.get('scans').get('Sophos'):
                                                    if response.get('scans').get('Sophos').get('detected') == True:
                                                        priorityCount+=1
                                                        
                                                Sucuri = response.get('scans').get('Sucuri SiteCheck').get('result') if response.get('scans').get('Sucuri SiteCheck') else ""
                                                if response.get('scans').get('Sucuri SiteCheck'):
                                                    if response.get('scans').get('Sucuri SiteCheck').get('detected') == True:
                                                        priorityCount+=1
                                                
                                                priorityCount = " {}/{}".format(priorityCount, "11")
                                                
                                                #A/AAAA Record Data
                                                #apikey= "29932dea25c8bf9c9dc1b712c746eba6f3617d697e1d4372e31b1290e48d8380"
                                                url3 = 'https://www.virustotal.com/vtapi/v2/domain/report'
                                                #parameters = {'domain': serverName, 'apikey': apikey}
                                                params = {'ip': resolved_IP, 'apikey': api_key}
                                                response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report',
                                                  params=params)
                                                  
                                                response_json = response.json() 
                                                asn = response_json.get("asn") if response_json.get("asn") else ""
                                                asOwner = response_json.get("as_owner") if response_json.get("as_owner") else ""
                                                asnCountry = response_json.get("country") if response_json.get("country") else ""
                                                
                                                
                                                
                                                cwriter.writerow([url,resolved_IP,scan_date,None,cats,vt_score,priorityCount,fpts,fpThreat,mbbr,ESET,Fortinet,Kaspersky,Trustwave, \
                                                AlienVault, BitDefender, googleSafebrowsing, Sophos, Sucuri, Domain_Name, Registrar_WHOIS_Server, Registrar_URL, registrar, Registrant_Name, \
                                                Registrant_Organization, country, Admin_Name, Admin_Organization, Admin_Country, Tech_Name, Tech_Organization, Tech_Country, \
                                                asn, asOwner, asnCountry])
                                        else:
                                                cwriter.writerow([url,None,None,result['error_msg'],None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None])
                                except Exception as e:
                                        cwriter.writerow([url,None,None,e,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None])
            
