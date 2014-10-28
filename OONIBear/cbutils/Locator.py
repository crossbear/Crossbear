import httplib
from BeautifulSoup import BeautifulSoup

def getCountry():
    conn = httplib.HTTPConnection("geoiptool.com")
    conn.request("GET", "/")
    resp = conn.getresponse()
    if resp.status != 200:
        print("Error %s retrieving Geo IP page: s" % (resp.status, resp.reason))
        return "XX"
    soup = BeautifulSoup(resp)
    try:
        code = soup.find(text="Country Code:").next.next.string
        if code == "":
            return "XX"
        return code.split(" ")[0]
    except AttributeError as e:
        print("Error parsing GeoIP page: %s" % e)
        return "XX"
        
