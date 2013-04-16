.PHONY: all little_bobby_tables tables indices

PSQL_FLAGS := 

# Default DB name
ifndef ASN_DB
    ASN_DB := asn
endif
ifndef ASN_SCHEMA
    ASN_SCHEMA := scan2
endif
ifndef ASN_USER
    ASN_USER := kulzer
endif
ifdef ASN_USER
    PSQL_FLAGS += -U $(ASN_USER) -W
endif


all:
	@echo "Use 'make tables' to create DB tables. Two envvars are supported:"
	@echo "ASN_SCHEMA - use different schema name than 'public'"
	@echo "ASN_DB - use different schema name than 'whois'"
	#@echo "Use 'make indices' to create search indices on already created tables"

tables: little_bobby_tables

little_bobby_tables:
	sql/makePrefix.sh $(ASN_SCHEMA) tables | psql $(PSQL_FLAGS) $(ASN_DB)

#indices:
#	sql/makePrefix.sh $(ASN_SCHEMA) indices | psql $(PSQL_FLAGS) $(ASN_DB)

