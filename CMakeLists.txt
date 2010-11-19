cmake_minimum_required (VERSION 2.6)

project (ITVal)

find_package(FLEX)
find_package(BISON)

FLEX_TARGET(MyScanner src/fwlang_scanner.ll ${CMAKE_CURRENT_BINARY_DIR}/fwlang_scanner.cc)
BISON_TARGET(MyParser src/fwlang.yy ${CMAKE_CURRENT_BINARY_DIR}/fwlang.cc)
ADD_FLEX_BISON_DEPENDENCY(MyScanner MyParser)

include_directories(${CMAKE_CURRENT_BINARY_DIR})


INCLUDE_DIRECTORIES(ITVal ${CMAKE_CURRENT_SOURCE_DIR}) 
add_executable(ITVal src/chains.cc src/debug.cc src/firewall.cc src/fwmdd.cc src/getline.cc src/iface.cc src/ITVal.cc src/nat.cc src/nat_iface.cc src/netconvert.cc src/parser.cc src/rule_parser.cc src/rules.cc src/sets.cc src/topology.cc ${FLEX_MyScanner_OUTPUTS} ${BISON_MyParser_OUTPUTS})

target_link_libraries(ITVal FDDL)

install (TARGETS ITVal DESTINATION bin) 
