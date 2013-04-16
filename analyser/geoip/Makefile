.PHONY: all little_bobby_tables tables indices

PSQL_FLAGS := 

# Default DB name
ifndef GEOIP_DB
    GEOIP_DB := geoip
endif
ifndef GEOIP_SCHEMA
    GEOIP_SCHEMA := scan2
endif
ifndef GEOIP_USER
    GEOIP_USER := kulzer
endif
ifdef GEOIP_USER
    PSQL_FLAGS += -U $(GEOIP_USER) -W
endif


all:
	@echo "Use 'make tables' to create DB tables. Two envvars are supported:"
	@echo "GEOIP_SCHEMA - use different schema name than 'public'"
	@echo "GEOIP_DB - use different schema name than 'whois'"
	#@echo "Use 'make indices' to create search indices on already created tables"

tables: little_bobby_tables

little_bobby_tables:
	sql/makePrefix.sh $(GEOIP_SCHEMA) tables | psql $(PSQL_FLAGS) $(GEOIP_DB)

#indices:
#	sql/makePrefix.sh $(GEOIP_SCHEMA) indices | psql $(PSQL_FLAGS) $(GEOIP_DB)

