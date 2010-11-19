/*
ITVal: The IPTables Firewall Validator
Copyright (C) 2004 Robert Marmorstein

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
A full-text version is located in the LICENSE file distributed with this
utility.

You may contact the author at rmmarm@wm.edu or by sending mail to:

Robert Marmorstein
Department of Computer Science
College of William and Mary
Williamsburg, VA 23185
*/

#ifndef __PARSER_H
#define __PARSER_H

#include "structures.h"
#include "fwmdd.h"

#define YY_DECL int yylex(YYSTYPE *yylval)

enum assertion_operators {OP_IS, OP_SUBSET, OP_NOT_IS, OP_NOT_SUBSET};

//A query condition.
class condition {
 public:
   mdd_handle h;
   mdd_handle history;
};

//A query, consisting of a subject (what info to display) and a
//condition (which packets to consider).
class query {
 public:
   int subject;                           //0 PACKET, 1 SADDY, 2 DADDY, 3 SPORT, 4 DPORT, 5 STATE
   condition *cond;
};

class assert {
   condition *left;
   condition *right;
   int op;
};

//Convert a port string into a port struct
port *ParsePort(char *str);

//Convert a port string into a port struct
address *ParseAddr(char *val1, char *val2, char *val3, char *val4);

//Returns the service associated with "name" or NULL if not found
service *ServiceLookup(char *name);

//Returns the group associated with "name" or NULL if not found
group *GroupLookup(char *name);

//Construct a new Service, consisting of the single port p
service *BuildServiceFromPort(port * p);

//Construct a new Group, consisting of the single address a
group *BuildGroupFromAddress(address * a);

//Construct a query condition representing the set of all logged
//packets.
condition *GetLoggedCondition(int input_chain);

//Construct a query condition representing the set of all packets
//accepted by chain "input_chain".
condition *BuildAcceptCondition(int input_chain);

//Construct a query condition representing the set of all packets
//dropped by chain "input_chain".
condition *BuildDropCondition(int input_chain);

//Construct a query condition from a group of addresses
condition *BuildConditionFromGroup(group * g, int op);

//Construct a query condition from a group of ports 
condition *BuildConditionFromService(service * g, int op);

//Construct a query condition from a specified state
condition *BuildConditionFromState(int state);

//Construct a query condition from a given network interface 
condition *BuildConditionFromIface(char *name, int in_out);

//Construct a query condition from a specified flag
condition *BuildConditionFromFlag(int flag);

//Create a query condition which is the negation of condition "c"
condition *NegateCondition(condition * c);

//Create a query condition which is the union of conditions "c1" and
//"c2".
condition *UnionConditions(condition * c1, condition * c2);

//Create a query condition which is the intersection of conditions "c1"
//and "c2".
condition *IntersectConditions(condition * c1, condition * c2);

//Intersect the set of accepted packets with the query filter and
//display the result.
query *PerformQuery(int s, condition * c);
assert *PerformAssertion(condition *left, condition *right, int assertion_operator, int example_flag, int history_flag);

//Compute Host Equivalence Classes and print them.
query *PrintClasses();
query *PrintServiceClasses();
query *PrintServiceGraph();
group *GetClasses();
service *GetServiceClasses();

//Add address "newAddy" to the linked list "list".
address *AppendAddy(address * list, address * newAddy);

//Add port "newPort" to the linked list "list".
port *AppendPort(port * list, port * newPort);

//Create an address group from a name and a list of addresses
group *DefineGroup(char *name, address * list);

//Create a service object from a name and a list of ports
service *DefineService(char *name, port * list);

//Create and initialize the MDD forest
void InitializeStructures(Firewall * F);

//Set the protocol of port "port" to "protocol"
port *BuildPort(int protocol, port * port);

void ParseQueryFile(char* filename);
#endif
