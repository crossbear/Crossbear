
import psycopg2
from ConfigParser import SafeConfigParser

class Scanner(object):
    def __init__(self, main_config_file_loc):
        """
        @param main_config_file_loc: location of the global.config
        """
        self.mainConfig = SafeConfigParser()
        self.mainConfig.read(main_config_file_loc)
        self.cache = {}
        self.db = psycopg2.connect(
            host = self.mainConfig.get("database", "host"),
            user = self.mainConfig.get("database", "user"),
            database = self.mainConfig.get("database", "dbname"),
            password = self.mainConfig.get("database", "password"))
        self.db.autocommit = True

    def cached(self, ip):
        if ip in self.cache:
            return True
        else:
            self.cache[ip] = 1
            return False
	
    def __del__(self):
        self.db.close()
