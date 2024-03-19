AM_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\"
LDADD = $(LIBINTL)

bin_PROGRAMS = gopenvpn
if INSTALL_GOVPNSTART
	bin_PROGRAMS += gopenvpnstart
endif

gopenvpn_LDADD = $(GTK_LIBS)	\
	$(LIBSECRET_LIBS)	\
	$(APPINDICATOR_LIBS)

AM_CFLAGS = -Wall -ansi -pedantic		\
	$(LIBSECRET_CFLAGS)			\
	$(APPINDICATOR_CFLAGS) \
	$(GTK_CFLAGS)				\
	-DPIXMAPS_DIR=\""$(datadir)/gopenvpn"\" \
	-DSYSCONF_DIR=\""$(sysconfdir)"\"	\
	-DLOCALE_DIR=\""$(localedir)"\"	\
	-DLOCALSTATE_DIR=\""$(localstatedir)"\"	\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"	\
	-DGTKBUILDER_DIR=\""$(datadir)/gopenvpn"\"

gopenvpn_SOURCES = gopenvpn.c gopenvpn.h gettext.h

if INSTALL_GOVPNSTART
	gopenvpnstart_SOURCES = gopenvpnstart.c
endif
