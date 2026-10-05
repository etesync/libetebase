PREFIX ?= /usr
DESTDIR ?=
# Set MODE to debug to build in debug mode
MODE ?= release

PKGNAME = etebase

# Library version from Cargo.toml, the soname major matches build.rs
VERSION := $(shell sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n 1)
VERSION_MAJOR := $(firstword $(subst ., ,$(VERSION)))

BUILDDIR = ./target

DST_LIBRARY_DIR = $(DESTDIR)$(PREFIX)/lib
DST_PKGCONFIG_DIR = $(DST_LIBRARY_DIR)/pkgconfig
DST_CMAKECONFIG_DIR = $(DST_LIBRARY_DIR)/cmake/Etebase
DST_INCLUDE_DIR = $(DESTDIR)$(PREFIX)/include/$(PKGNAME)

LIBRARY_FILE = $(BUILDDIR)/$(MODE)/lib$(PKGNAME).so
HEADER_FILE = $(BUILDDIR)/$(PKGNAME).h
PKGCONFIG_FILE = $(BUILDDIR)/$(PKGNAME).pc
CMAKECONFIG_FILE = EtebaseConfig.cmake

.PHONY: default all clean

all: build

pkgconfig: $(PKGCONFIG_FILE)

$(PKGCONFIG_FILE): $(PKGNAME).pc.in
	mkdir -p "$(BUILDDIR)"
	sed "s#@prefix@#$(PREFIX)#g" $< > "$(BUILDDIR)/$(PKGNAME).pc"

build-release: pkgconfig
	cargo build --release

build-debug: pkgconfig
	cargo build

build: build-$(MODE)

install:
	install -Dm644 "$(PKGCONFIG_FILE)" -t "$(DST_PKGCONFIG_DIR)"
	install -Dm644 "$(CMAKECONFIG_FILE)" -t "$(DST_CMAKECONFIG_DIR)"
	install -Dm644 "$(HEADER_FILE)" -t "$(DST_INCLUDE_DIR)"
	install -Dm755 "$(LIBRARY_FILE)" "$(DST_LIBRARY_DIR)/lib$(PKGNAME).so.$(VERSION)"
	ln -sf "lib$(PKGNAME).so.$(VERSION)" "$(DST_LIBRARY_DIR)/lib$(PKGNAME).so.$(VERSION_MAJOR)"
	ln -sf "lib$(PKGNAME).so.$(VERSION_MAJOR)" "$(DST_LIBRARY_DIR)/lib$(PKGNAME).so"

check: build
	cargo check
	cd c_tests && $(MAKE) check

clean:
	cargo clean
	cd c_tests && $(MAKE) clean
	rm -f "$(BUILDDIR)/$(PKGNAME).p"c
