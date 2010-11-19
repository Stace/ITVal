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

#ifndef __RULE_PARSER_H__
#   define __RULE_PARSER_H__

#   include <stdlib.h>
#   include "topology.h"


//An unprocessed rule grabbed straight from the text file.
class rule {
 public:
   int id;
   int chain_id;
   int fw_id;
   char text[2048];
   char target[256];
   char protocol[256];
   char opt[256];
   char source[256];
   char dest[256];
   char in[256];
   char out[256];
   char info[256];
   int pktCond;
   rule *next;

     rule() { 
	id = -1;
	chain_id = -1; //No chain.
	fw_id = -1; // No FW.
      next = NULL;
}};

class rule_parser {
   Topology *top;
 public:
   void BreakPort(char *word, char *which, char *port);
   void BreakState(char *word, int *state);
   void BreakFlags(char *word, int *flags);
   void BreakPktType(char *word, int& type);
     rule_parser(Topology * t) {
      top = t;
   } int ReadRule(rule * newRule, char *line, size_t length);
   int ReadVerboseRule(rule * newRule, char *line, size_t length);
};
#endif
