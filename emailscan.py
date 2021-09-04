import requests
import json
import urllib.request

menu = """
[1]Email Details
[2]Email Scan Breached/Not
[3]Exit
"""
print(menu)

key = "VrzIuNfj27KXWnHHALabdRqfBowBVciW"

def scan():

    try:
        option = input("[+] Enter the option do you Want : ")
        mail = input("[+] Enter The Email : ")          
        if option == "1":
            print('')
            print("Email Details results for",mail)
            print('')
            print("Processing Mail : ",mail)
            api = "https://ipqualityscore.com/api/json/email/"+key+"/"+mail+""
            response = urllib.request.urlopen(api)
            data = response.read()
            value = json.loads(data)
            print('')
            print("[+] Success Status: " + str(value['success']))
            print("[+] Valid: " + str(value['valid']))
            print("[+] Disposable: " + str(value['disposable']))
            print("[+] Honeypot: " + str(value['honeypot']))
            print("[+] Smtp Score: " + str(value['smtp_score']))
            print("[+] Overall Score: " + str(value['overall_score']))
            print("[+] First Name: " + str(value['first_name']))
            print("[+] Generic: " + str(value['generic']))
            print("[+] Dns Valid: " + str(value['dns_valid']))
            print("[+] Deliverability: " + str(value['deliverability']))
            print("[+] Frequent Complainer: " + str(value['frequent_complainer']))
            print("[+] Spam Trap: " + str(value['spam_trap_score']))
            print("[+] Catch All: " + str(value['catch_all']))
            print("[+] Time Out: " + str(value['timed_out']))
            print("[+] Abused Recently: " + str(value['recent_abuse']))
            print("[+] Fraud Score: " + str(value['fraud_score']))
            print("[+] Suggested Domain: " + str(value['suggested_domain']))
            print("[+] Leaked: " + str(value['leaked']))
            print("[+] Domain Age Human: " + str(value['domain_age']['human']))
            print("[+] Time Stamp: " + str(value['domain_age']['timestamp']))
            print("[+] ISO: " + str(value['domain_age']['iso']))
            print("[+] First Seen: " + str(value['first_seen']['human']))
            print("[+] First Seen Timestamp: " + str(value['first_seen']['timestamp']))
            print("[+] First Seen ISO: " + str(value['domain_age']['iso']))
            print("[+] Sanitized Email: " + str(value['sanitized_email']))
            print("[+] Request ID: " + str(value['request_id']))
            print('')
            if value['disposable'] == True:
                print("[+] It is Temporary/Disposable Mail...")
            else :
                print("[+] It is Not Temporary/Disposable Mail...")
                print('')

        if option == "2":
            print('')
            print("[+] Checking for Breached Email...")
            print("Email Breach results for",mail)
            print("-------------------------------------------------------------------------------------")
            url = "https://haveibeenpwned.com/api/v3/breachedaccount/"+mail
            header = {'hibp-api-key':'58779e4f5a4d427a9cb3175dcc3b3f58'}
            print('')
            print("Checking for Breached Data....")
            print('')
            print("**************************************************************************************")
            rqst = requests.get(url,headers=header,timeout=10)
            sc = rqst.status_code
            if sc == 200:
                print("The Email has been Breached")
                json_out = rqst.content.decode('utf-8', 'ignore')
                simple_out = json.loads(json_out)
                for item in simple_out:
                    print('\n'
                    '[+] Breached From : ' + str(item['Name']))
            elif sc == 404:
                print('[+] The Email is Not Breached')
            elif sc == 503:
                print('\n')
                print('[-] Error 503 : Request Blocked by Cloudflare DDoS Protection')
            elif sc == 403:
                print('\n')
                print('[-] Error 403 : Request Blocked by haveibeenpwned API')
                print(rqst.text)
            else:
                print('\n')
                print('[-] An Unknown Error Occurred')
                print(rqst.text)       

        elif option =='4':
            exit()

    except KeyboardInterrupt:
        print("\nAborted!")
        quit()
    except:
        print("Invalid Option !\n")
        return scan()
scan()
