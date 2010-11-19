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


#ifndef __RULES_H__
#   define __RULES_H__

#   include "ranges.h"
#   include "topology.h"
#   include "rule_parser.h"
#   include <stdio.h>

//A processed rule, in which the addresses and ports
//have been broken into lists of ranges.
class processed_rule {
 public:
   int id;
   int chain_id;
   address_range *from;
   address_range *to;

   char protocol;
   port_range *sports;
   port_range *dports;
   int in;
   int out;
   int state;
   int flags[6];
   int pktcond;

   char target[256];
   processed_rule *next;

     processed_rule() {
      from = new address_range;
      to = new address_range;
      sports = NULL;
      dports = NULL;
      next = NULL;
      in = -1;
      out = -1;
      id = -1;
      chain_id = -1;
     } 
     ~processed_rule() {
      port_range *cur;
      delete from;
      delete to;

      while (sports != NULL) {
         cur = sports;
         sports = sports->next;
         delete cur;
      }
      while (dports != NULL) {
         cur = dports;
         dports = dports->next;
         delete cur;
      }
   }
};

//A tuple of elements suitable for insertion
//into an MDD.
class rule_tuple {
 public:
   int hlow[25];
   int hhigh[25];
   int low[23];
   int high[23];
   int id;
   int chain_id;
   rule_tuple *next;

     rule_tuple() {
	id = -1;
	chain_id = -1;
      next = NULL;
}};

//A helper function for converting unprocessed rules
//into processed_rules.
void ProcessRule(rule * r, processed_rule * p, rule_parser * rp,
                 Topology * h);
#endif
