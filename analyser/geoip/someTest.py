import GeoIP

# For the country based queries.
gir = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)

# For City based queries
gi = GeoIP.open("GeoLiteCity.dat",GeoIP.GEOIP_STANDARD)

print gir.country_code_by_addr("131.159.20.21")
print gir.country_name_by_name('google.com')

# retrieve ORG database as well
#print gir.org_by_name("spiegel.de")

print gi.record_by_name("facebook.com")
iprange = gi.range_by_ip("131.159.20.21")
print iprange[0]

# retrieve region db if necessary
#print gi.region_by_name("heise.de")
