NAME=$(shell basename $$(pwd))
PATHS=$(shell ls -d bin lib 2>/dev/null)

.PHONY: build
build:
	@if [ -n "$(shell git diff --stat)" ]; then echo "Git repo is dirty" ; exit 1; fi
	@if [ -z "$(shell git describe --tags --exact-match)" ]; then echo "Current commit isn't tagged" ; exit 1; fi
	mkdir -p dist
	rm -f dist/*
	tar czf dist/$(NAME)_$(shell git describe --tags --exact-match).tar.gz $(PATHS)
	cd dist && shasum -a 512 ./$(NAME)_$(shell git describe --tags --exact-match).tar.gz > sha512-checksums.txt

.PHONY: clean
clean:
	rm -rf dist
