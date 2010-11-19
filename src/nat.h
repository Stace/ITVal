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

#ifndef __NAT_H__
#   define __NAT_H__

#   include "ranges.h"
#   include "rules.h"
#   include "rule_parser.h"

#   include <stdio.h>

class Firewall;

class nat_range {
 public:
   address_range addys;
   port_range ports;
   nat_range *next;

   int low[23];
   int high[23];

     nat_range() {
      next = NULL;
}};

class nmap_range {
 public:
   address_range addys;
   port_range ports;
   nmap_range *next;

   int mask;

   int low[23];
   int high[23];

     nmap_range() {
      next = NULL;
}};

class nat_tuple:public rule_tuple {
 public:
   nat_range * nat;

   nat_tuple():rule_tuple() {
      nat = NULL;
}};

//A processed rule from the NAT file,
//in which the addresses and ports have been broken into lists of ranges.
class processed_nat_rule:public processed_rule {
 public:
   nat_range * nat;
   processed_nat_rule():processed_rule() {
      nat = NULL;
   } ~processed_nat_rule() {
      while (nat != NULL) {
         nat_range *cur;
         cur = nat;
         nat = nat->next;
         delete cur;
      }
   }
};

//A helper function for converting unprocessed rules
//into processed_rules.
void ProcessNATRule(rule * r, processed_nat_rule * p, Firewall * FW,
                    rule_parser * rp);
void ConvertNATRules(processed_nat_rule * pnr, nat_tuple * &stack);
#endif
