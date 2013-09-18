#!/usr/bin/python
#   This file uses all Geo location services and executes them requests
#
#   Copyright (C) 2012 Robert Kulzer
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, version 3 of the License.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

#from IpDbParser import IpDbParser
import MaxMind as MaxMind
from misc.Scanner import Scanner

class GeoIPScanner(Scanner):
	def __init__(self, main_config_file_loc):
		super(GeoIPScanner, self).__init__(main_config_file_loc)
		# Fetch information regarding MaxMind DB from global config file
		self.dbpath = self.mainConfig.get("geoloc", "dbpath")
		self.maxMind = MaxMind.MaxMind(self.dbpath)

	def start_scan(self, ips):
		cur = self.db.cursor()
		sql = "INSERT INTO geo_results (ip, city, region_name, region, time_zone, longitude, latitude, metro_code, country_code, country_code3, country_name, postal_code, dma_code, ipStart, ipEnd) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);"
		for ip in ips:
                        if not self.cached(ip):
                                record = self.maxMind.queryDB(ip)
                                cur.execute(sql, tuple([record[i] for i in ['address', 'city', 'region_name', 'region', 'time_zone', 'longitude', 'latitude', 'metro_code', 'country_code', 'country_code3', 'country_name', 'postal_code', 'dma_code', 'ipStart', 'ipEnd']]))
                                cur.close()


if __name__ == "__main__":
	import misc.DomainHandler
	ips = misc.DomainHandler.IPSupplier("geoip.config")
	asns = GeoIPScanner("geoip.config")
	asns.start_scan(ips.get(1))

