
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

#ifndef __CHAINS_H
#   define __CHAINS_H

#   include <stdio.h>
#   include <stdlib.h>
#   include <string.h>

#   include "rules.h"
#   include "nat.h"


class chain {
 public:
 int numRules;
 static int numChains;
   int id;			      //integer id of chain.
   char name[256];                    //Name of the chain
   char fname[256];                   //For debugging, name of the file.
   int Default;                       //Default policy of the chain.

   rule *rules;                       //List of original, unprocessed, rules
   processed_rule *newRules;          //List of intermediate, expanded, rules
   rule_tuple *tup;                   //List of tuples

     chain() {
      rules = NULL;
      newRules = NULL;
      tup = NULL;
      Default = -1;
      chain::numChains++;
      id = chain::numChains;
      numRules = 1;  //Default policy counts as rule 0.
     } 
     
     chain(char *fileName) {
      rules = NULL;
      newRules = NULL;
      tup = NULL;
      Default = -1;
      strncpy(fname, fileName, 256);
      chain::numChains++;
      id = chain::numChains;
      numRules = 1;  //Default policy counts as rule 0.
   }

   ~chain() {
      rule *cur_rule;
      processed_rule *cur_prule;
      rule_tuple *cur_tup;

      while (rules != NULL) {
         cur_rule = rules;
         rules = rules->next;
         delete cur_rule;

         cur_rule = NULL;
      }

      while (newRules != NULL) {
         cur_prule = newRules;
         newRules = newRules->next;
         delete cur_prule;
      }

      while (tup != NULL) {
         cur_tup = tup;
         tup = tup->next;
         delete cur_tup;
      }
   }

   rule_tuple* FindRule(int rule_id);
};

class nat_chain:public chain {
 public:
   processed_nat_rule * natRules;
   nat_chain(char *fileName):chain(fileName) {
      natRules = NULL;
   } ~nat_chain() {
      processed_nat_rule *cur_nrule;
      cur_nrule = natRules;
      while (natRules != NULL) {
         cur_nrule = natRules;
         natRules = (processed_nat_rule *) natRules->next;
         delete cur_nrule;
      }
   }
};

//Given the name of a chain, find its index in the chain array
int FindNATChain(char *name);
#endif
