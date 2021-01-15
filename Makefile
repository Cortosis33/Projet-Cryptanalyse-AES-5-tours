# Variables
EXE = AES_TEST

# Special rules and targets
.PHONY: all build clean help

# Rules and targets
all: build

build:
	@cd src && $(MAKE)
	@cp -f src/$(EXE) ./
	@cd src && make clean

clean:
	@cd src && $(MAKE) clean
#	@cd test && $(MAKE) clean
	@rm -f $(EXE)

help:
	@echo "Usage:"
	@echo " make [all]\t\tBuild"
	@echo " make build\t\tBuild the software"
	@echo " make clean\t\tRemove all files generated by make"
	@echo " make help\t\tDisplay this help"
