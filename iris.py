# Internet Vulnerability Scanner and Reporting Tool

import shodan, datetime, nested_lookup

print("""
    Welcome to IRIS! In order to use this program, you need a Shodan API key.
    You can get one by signing up to the Shodan service here: https://account.shodan.io/register
""")
api_key = raw_input("Please input a valid Shodan API key: ")
print("Connecting to Shodan...")

try:
    api = shodan.Shodan(api_key)# Shodan API initialisation.
    keyinfo = api.info()
except:
    print("An error occured, be sure to check your API key, internet connection and if Shodan is accessible.")
    quit()

def main():
    while True:
        print('''
      .         .            .          .       .
            .         ..xxxxxxxxxx....               .       .             .
    .             MWMWMWWMWMWMWMWMWMWMWMWMW                       .
              IIIIMWMWMWMWMWMWMWMWMWMWMWMWMWMttii:        .           .
 .      IIYVVXMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWxx...         .           .
     IWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMWMx..
   IIWMWMWMWMWMWMWMWMWBY%ZACH%AND%OWENMWMWMWMWMWMWMWMWMWMWMWMWMx..        .
    ""MWMWMWMWMWM"""""""".  .:..   ."""""MWMWMWMWMWMWMWMWMWMWMWMWMWti.
 .     ""   . `  .: . :. : .  . :.  .  . . .  """"MWMWMWMWMWMWMWMWMWMWMWMWMti=
        . .   :` . :   .  .'.' '....xxxxx...,'. '   ' ."""YWMWMWMWMWMWMWMWMWMW+
     ; . ` .  . : . .' :  . ..XXXXXXXXXXXXXXXXXXXXx.    `     . "YWMWMWMWMWMWMW
.    .  .  .    . .   .  ..XXXXXXXXWWWWWWWWWWWWWWWWXXXX.  .     .     """""""
        ' :  : . : .  ...XXXXXWWW"   W88N88@888888WWWWWXX.   .   .       . .
   . ' .    . :   ...XXXXXXWWW"    M88N88GGGGGG888^8M "WMBX.          .   ..  :
         :     ..XXXXXXXXWWW"     M88888WWRWWWMW8oo88M   WWMX.     .    :    .
           "XXXXXXXXXXXXWW"       WN8888WWWWW  W8@@@8M    BMBRX.         .  : : 
  .       XXXXXXXX=MMWW":  .      W8N888WWWWWWWW88888W      XRBRXX.  .       .   
     ....  ""XXXXXMM::::. .        W8@889WWWWWM8@8N8W      . . :RRXx.    .
         ``...''"  MMM::.:.  .      W888N89999888@8W      . . ::::"RXV    .  :
 .       ..'"'"      MMMm::.  .      WW888N88888WW     .  . mmMMMMMRXx
      ..' .            ""MMmm .  .       WWWWWWW   . :. :,miMM"'  : ''`    .
   .                .       'MMMMmm . .  .  .   ._,mMMMM"'  :  ' .  :
               .                  ""'MMMMMMMMMMMMM"' .  : . '   .        .
          .              .     .    .                      .         .
.                                         .          .         .     
                    IRIS - Initial Recon Internet Scanner 

    [1] Scan for vulnerable hosts.
    
    [0] Quit.
    ''')
        valid_opts = {"0", "1"}
        opt = raw_input(">")
        if (opt in valid_opts) == True:
            pass
        else:
            print("Invalid option, please try again.")
            main()
        if opt == "0":
            print("Quitting...")
            quit()
        if opt == "1":
            apiCall()


def deviceInfo():
    print("Gathering vulnerability data...")
    timestamp = datetime.date.today()# Retrieves current date in YYYY-MM-DD format.
    fname_raw = "IRIS-raw-"+query+"-"+str(timestamp)+".txt"# Creates filename for raw JSON to be created/opened later on.
    fname_cve = "IRIS-cve-"+query+"-"+str(timestamp)+".txt"# Creates filename for CVE and CVSS scores to be created.
    keys = nested_lookup.get_all_keys(page)# Gets all keys for the nested dictionary.
    device_ips = []
    device_cves = []
    device_cvss = []
    vuln_counter = 0
    for ip in nested_lookup.nested_lookup('ip_str', page):# Sorts IP addresses and removes dupes. Shoutout to Jack for showing me nested_lookup.
        if ip in device_ips:
            continue
        else:
            device_ips.append(ip)
    for cve in keys:
        if str(cve).startswith('CVE-'):
            device_cves.append(cve)
            vuln_counter += 1
    for cvss in nested_lookup.nested_lookup('cvss', page):
        device_cvss.append(float(cvss))
    f_cve = open(fname_cve, "a")
    for n in range(0, vuln_counter):
        vuln_print = str(device_cves[int(n)]) + " - Severity: "+ str(device_cvss[int(n)]) + " - " + "https://www.cvedetails.com/cve/"+str(device_cves[int(n)] + "\n")
        f_cve.write(str(vuln_print))# Appends CVEs and CVSS scores to file.
    print("Saving found vulnerabilities to " + str(fname_cve))
    f_cve.close()
    f_raw = open(fname_raw, "w")
    f_raw.write(str(page))
    print("Saving raw JSON output to " + str(fname_raw))
    f_raw.close()



def apiCall():
    global page
    global total
    global pageno_range
    global query
    print("""
    This module will use the Shodan API to collect hosts based on given input.
    If any known vulnerabilities exist within the host, IRIS will retrieve CVE information and include it in the final report.
    Once all potentially vulnerable hosts have been harvested, you will be given a text file with CVE IDs and CVSS scores found during the scan.

    WARNING: Please be aware that your account may only have a limited amount of credits, and larger searches may exceed this limit.
             Check here for further information: https://help.shodan.io/the-basics/credit-types-explained

             To learn more about Shodan query strings, see: https://help.shodan.io/the-basics/search-query-fundamentals

             Remaining query credits: %s
    """% (keyinfo['query_credits']))
    query = raw_input("Please enter your query> ")
    if query == '':
        print("Blank query submitted! Returning to main menu...")
        main()
    print("Gathering host information...")
    pageno = []# Number list must be generated based on amount of total hosts. 
    #NOTE: 100 hosts per page. So 416 pages will require ints 1 to 5 in the list.
    try:
        initial_search = api.search(query)
    except:
        print("An error occured, be sure to check your API key, internet connection and if Shodan is accessible.")
        main()
    total = (initial_search['total'])# Grabs first page and total host amount.
    page = {}# Initial dictionary to house nested dicts for each page.
    if total < 100:
        divide = 1
    else:
        divide = total / 100
        if (total % 100) != 0:
            divide += 1
    pageno_range = range(1, divide+1)
    for n in pageno_range:
        pageno.append(n)# Generates the list of page numbers.
        page[n] = {}# Generates nested dicts within page dict.
    for n in pageno:
        try:
            print("Gathering results ("+str(n)+"/"+str(divide)+")...")
            search = api.search(query, page=n)
            page[n] = search# Loops through dictionaries filling them with 100 hosts each.
        except:# This should only really be thrown with a connection error, or if user CTRL+C's.
            print("An exception occured, this is normally due to a timeout while requesting data from the Shodan API.")
            error_opt = raw_input("Do you want to [retry] data collection or [stop] data collection? (retry|stop): ")
            if error_opt == "retry":
                print("Resuming data collection...")
                try:
                    del page[n-1]# Deletes nested dict and retries from scratch.
                    retry_current = api.search(query, page=n-1)
                except:
                    retry_current = api.search(query, page=n)
                print("Gathering results ("+str(n)+"/"+str(divide)+")...")
                pass
            if error_opt == "stop":
                print("Returning to main menu...")
                main()
    deviceInfo()
main()

