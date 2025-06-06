#
# Makefile for mod_auth_tacacs
#

# "libauth_tacacs" library name should be kept, it is the only choice:
# * it may be compiled as ".so" and various tools require "lib" for ".so" files
# * "libmod_" will not be stripped by apache/src/Configure which strips
#   either "lib" prefix or "mod_" but never both at once
# * we can choose another name when build ".a" but we want to keep the same
#   name for the same thing all the time

# "auth_tacacs" (directory, module name etc.) and NOT "mod_auth_tacacs" as:
# * standard is not to include "mod_" in "src/modules/DIRECTORY_NAME"
# * "mod_" gets sometimes stripped down by Apache scripts
# * we want to keep as close to "libauth_tacacs" filename as possible

# "auth_tacacs" module name and NOT "tacacs_auth' as:
# * Apache standard is to PREFIX authorization modules by "auth_"
# * source file name "mod_auth_tacacs.c" provoke for it


# Move "tacacs_testclient" from "noinst_PROGRAMS" into new "bin_PROGRAMS"
# if you want to get it installed by "make install"

noinst_PROGRAMS			= \
	tacacs_testclient \
	$(mod_as_shared)

if BUILD_WITH_APXS
mod_as_shared		= \
	libauth_tacacs.so
endif

libauth_tacacs_so_SRCS	= \
	mod_auth_tacacs.c \
	$(libtac_SRCS)
libauth_tacacs_so_HDRS	= \
	$(libtac_HDRS)

# Keep in sync with _OBJECTS{,_PIC} in Makefile.tmpl !
libauth_tacacs_so_SOURCES	= \
	$(libauth_tacacs_so_SRCS) \
	$(libauth_tacacs_so_HDRS)

APACHE_INSTALL_FILES_CORE	= \
	Makefile.tmpl Makefile.libdir
APACHE_INSTALL_FILES		= \
	$(APACHE_INSTALL_FILES_CORE) \
	config.h \
	$(libauth_tacacs_so_SOURCES)

libtac_SRCS			= \
	mod_tac_utils.c \
	mod_tac_packet.c \
	mod_tac_authen.c \
	mod_tac_author.c \
	mod_tac_account.c \
	md5.c
libtac_HDRS			= \
	mod_tac.h \
	md5.h
libtac_SRCSHDRS		= \
	$(libtac_SRCS) \
	$(libtac_HDRS)

tacacs_testclient_SOURCES	= \
	tacacs_testclient.c \
	$(libtac_SRCS) \
	$(GETOPT_SRCS)
EXTRA_tacacs_testclient_SOURCES = \
	getopt.c getopt1.c getopt.h

EXTRA_DIST			= \
	README AUTHORS COPYING ChangeLog INSTALL NEWS \
	$(APACHE_INSTALL_FILES_CORE) \
	tacacs_testclient_test

comma = ,

# "rm -f" reason:
# We never leave any *.o file on disk as we are compiling the same
# sources/objects with DIFFERENT compiler flags while building
# "tacacs_testclient" vs. "libauth_tacacs.so"
# cons: We always must recompile ALL the source file for the target
#       but it is not interesting as the source files are very small

tacacs_testclient: $(tacacs_testclient_SOURCES)
	rm -f $(tacacs_testclient_OBJECTS)
	$(COMPILE) -c $^
	$(LINK) $(tacacs_testclient_OBJECTS) $(GETOPT_OBJS) $(LIBS)
	rm -f $(tacacs_testclient_OBJECTS)

if BUILD_WITH_APXS
libauth_tacacs.so: $(libauth_tacacs_so_SOURCES)
	rm -f $(libauth_tacacs_so_OBJECTS)
	$(APXS) -c $(DEFS) $(CPPFLAGS) \
			$(addprefix -Wc$(comma),$(CFLAGS)) \
			$(addprefix -Wl$(comma),$(LDFLAGS)) \
			$(LIBS) \
			-o $@ $(libauth_tacacs_so_SRCS)
	rm -f $(libauth_tacacs_so_OBJECTS)
endif

if BUILD_WITH_APXS
install-exec-local: libauth_tacacs.so
	$(APXS) -i -a -n auth_tacacs $^
else
install-exec-local: $(APACHE_INSTALL_FILES)
	mkdir -p $(APACHE_TARGET)
	cp -p $^ $(APACHE_TARGET)/
	@echo 'Use the following keywords for APACI configure:'
	@echo '	--activate-module=src/modules/auth_tacacs/libauth_tacacs.a'
	@echo '	--enable-module=auth_tacacs'
endif
