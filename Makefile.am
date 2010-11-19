BUILT_SOURCES = src/fwlang.tab.hh
AM_YFLAGS = -d
bin_PROGRAMS = ITVal #xITVal

ITVal_SOURCES = src/fwlang_scanner.ll src/fwlang.yy src/ITVal.cc src/chains.cc src/debug.cc src/firewall.cc src/iface.cc src/nat.cc src/nat_iface.cc src/netconvert.cc src/rule_parser.cc src/rules.cc src/parser.cc src/fwmdd.cc src/topology.cc src/chains.h src/debug.h src/firewall.h src/fwmdd.h src/iface.h src/nat.h src/ranges.h src/rule_parser.h src/rules.h src/stack.hh src/parser.h src/topology.h src/getline.cc src/sets.h src/sets.cc src/structures.h

#xITVal_SOURCES = src/fwlang_scanner.ll src/fwlang.yy gui/PythonPipe.cc gui/PythonPipe.h gui/xITVal.cc src/chains.cc src/debug.cc src/firewall.cc src/iface.cc src/nat.cc src/nat_iface.cc src/netconvert.cc src/rule_parser.cc src/rules.cc src/parser.cc src/fwmdd.cc src/topology.cc src/chains.h src/debug.h src/firewall.h src/fwmdd.h src/iface.h src/nat.h src/ranges.h src/rule_parser.h src/rules.h src/stack.hh src/parser.h src/topology.h src/getline.cc gui/gui.py src/sets.h src/sets.cc src/structures.h

man_MANS = man/ITVal.n

ITVal_LDADD = @LEXLIB@ FDDL/libFDDL.la

#xITVal_LDADD = @LEXLIB@ FDDL/libFDDL.la

EXTRA_DIST = COPYING ChangeLog LICENSE man/ITVal.n src/fwlang.tab.hh fwlang.cc fwlang_scanner.cc RELEASE

SUBDIRS = FDDL doc

ACLOCAL_AMFLAGS = -I m4
