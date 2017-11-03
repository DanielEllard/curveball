# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contract No. N66001-11-C-4017.
#
# Copyright 2014 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

# This is a Makefile for click plus the BBN Curveball click elements,
# intended to be used for use with BBN Curveball.
#
# DOES NOT SUPPORT ALL OF THE FEATURES SUPPORTED BY STANDARD CLICK.
# DOES NOT SUPPORT LINUX KERNEL MODULES, SOME DRIVERS, AND SOME
# ELEMENTS.
#
# NOTE:
# We assume that NO other version of click is already installed.  If
# another version of click is installed, then we try to detect this
# and fail.  This can be overridden by removing the test_click_version
# from the build, but this will clobber whatever was installed, with
# unpredictable and often undesirable results.
#
# (At some point we might want to install our version of click in its
# own directory, instead of /usr/local/, but we're not doing that yet.)

CLICK_VERSION	= 01102014cb
CLICK_DIR	= click-$(CLICK_VERSION)

CLICK_OPTIONS	= --disable-linuxmodule
CBCLICK_OPTIONS	=
SUDO		= /usr/bin/sudo
MAKEFILE	= $(lastword $(MAKEFILE_LIST))
SRCDIR_FILE	= /usr/local/share/click/srcdir

# test whether there's any version of click installed, and if so
# whether it matches the version we want to build, and halts if
# there's a version and it doesn't match what we need.  Otherwise,
# builds/installs the base click, and then builds/installs the
# BBN Curveball elements.
#
build:
	$(MAKE) -f $(MAKEFILE) test_click_version
	$(MAKE) -f $(MAKEFILE) base_click
	cd curveball && $(SUDO) ./configure $(CBCLICK_OPTIONS)
	cd curveball && $(SUDO) $(MAKE) install

# Only builds/installs the BBN Curveball elements.
#
cbbuild: $(SRCDIR_FILE)
	$(MAKE) -f $(MAKEFILE) test_click_version
	cd curveball && $(SUDO) ./configure $(CBCLICK_OPTIONS)
	cd curveball && $(SUDO) $(MAKE) install

# if $SRCDIR_FILE does not exist, then click isn't installed (or isn't
# where we think it should be), so we need to do an install.
#
$(SRCDIR_FILE):
	$(MAKE) -f $(MAKEFILE) base_click

# If there is a version installed, then we need to check whether it's
# the version we are about to install.  If not, then gripe.
#
test_click_version:
	@test ! -f $(SRCDIR_FILE) \
	|| test $$(cat $(SRCDIR_FILE) | sed -e 's/.*\/click-//' ) \
	    = $(CLICK_VERSION) \
	|| (echo "" && \
	    echo "ERROR: CLICK VERSION MISMATCH: wrong version installed:" && \
	    cat $(SRCDIR_FILE) && \
	    echo "" && \
	    false)

$(CLICK_DIR):
	$(SUDO) apt-get install linux-headers-$(shell uname -r)
	@echo "Untarring $@"
	$(SUDO) /bin/tar zxf $@.tar.gz

base_click:
	$(MAKE) -f $(MAKEFILE) $(CLICK_DIR)
	cd $(CLICK_DIR) && $(SUDO) ./configure $(CLICK_OPTIONS)
	cd $(CLICK_DIR) && $(SUDO) $(MAKE) install

clean:	$(CLICK_DIR)
	cd $(CLICK_DIR) && $(SUDO) $(MAKE) clean
	cd curveball && $(SUDO) $(MAKE) clean
	cd curveball && $(SUDO) ./configure $(CBCLICK_OPTIONS)

# Not really spotless, because it doesn't uninstall.  It only cleans up the
# build area.
#
spotless:
	$(SUDO) /bin/rm -rf $(CLICK_DIR)

