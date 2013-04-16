.PHONY: all little_bobby_tables tables indices

PSQL_FLAGS := 

# Default DB name
ifndef WHOIS_DB
    WHOIS_DB := whois
endif
ifndef WHOIS_SCHEMA
    WHOIS_SCHEMA := scan2
endif
ifndef WHOIS_USER
    WHOIS_USER := kulzer
endif
ifdef WHOIS_USER
    PSQL_FLAGS += -U $(WHOIS_USER) -W
endif


all:
	@echo "Use 'make tables' to create DB tables. Two envvars are supported:"
	@echo "WHOIS_SCHEMA - use different schema name than 'public'"
	@echo "WHOIS_DB - use different schema name than 'whois'"
	#@echo "Use 'make indices' to create search indices on already created tables"

tables: little_bobby_tables

little_bobby_tables:
	sql/makePrefix.sh $(WHOIS_SCHEMA) tables | psql $(PSQL_FLAGS) $(WHOIS_DB)

#indices:
#	sql/makePrefix.sh $(WHOIS_SCHEMA) indices | psql $(PSQL_FLAGS) $(WHOIS_DB)

