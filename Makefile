SERVERDIR = cmd/server
CLIENTDIR = cmd/client

#run:
#	@cd bin && ./dcdr-server
run-server: 
	@cd cmd/server go run main.go

run-client:
	@cd cmd/client go run main.go

build:
	@echo "Building dcdr server"
	@cd $(SERVERDIR) && go build -o ../../bin/dcdr-server main.go
	@echo "Done!"
	@echo "Building dcdr client"
	@cd $(CLIENTDIR) && go build -o ../../bin/dcdr main.go
	@echo "Done!"

drop:
	@echo "Dropping dcdr database"
	@./tools/sh/drop_db.sh
	@echo "Done!"

init:
	@echo "Creating dcdr database"
	@./tools/sh/init_db.sh
	@echo "Done!"

seed:
	@echo "Seeding database for testing"
	@./tools/sh/create_app.sh
	@echo "Done!"

clean-backends:
	@echo "Running clean scripts"
	@python3 tools/python/clean_vault.py
	@python3 tools/python/clean_bao.py

stats:
	@echo "Refreshing project statistics"
	@cloc . | tee stats.txt
	@tree | tee -a stats.txt
	@echo "Done!"