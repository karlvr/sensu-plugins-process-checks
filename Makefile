.PHONY: build
build:
	@if [ -n "$(shell git diff --stat)" ]; then echo "Git repo is dirty" ; exit 1; fi
	@if [ -z "$(shell git describe --tags --exact-match)" ]; then echo "Current commit isn't tagged" ; exit 1; fi
	mkdir -p dist
	rm -f dist/*
	tar czf dist/assets_$(shell git describe --tags --exact-match).tar.gz bin
	cd dist && shasum -a 512 ./assets_$(shell git describe --tags --exact-match).tar.gz > sha512-checksums.txt
