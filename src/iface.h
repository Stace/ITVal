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
#include <FDDL/mdd.h>
#include "rules.h"
#include "chains.h"

#define NUM_DEFAULT_TARGETS 4
enum targets { SNAT = -3, DNAT = -2, LOG = -1, UNDEFINED = 0, RETURN = 0, DROP
   = 1, REJECT = 2, ACCEPT = 3, REDIRECT = -4, MASQUERADE = -5, NETMAP = -6 };

enum protocols { ICMP = 0, UDP = 1, TCP = 2 };

void PrintRuleTuple(rule_tuple * r);
void BuildRules(processed_rule * head, rule_tuple * &result);
void ApplyNATRules(processed_nat_rule * head, rule_tuple * &result);
void AssembleChains(chain ** chain_array, chain * chain,
                    mdd_handle & outputMDD, mdd_handle & logMDD);
void NATChains(chain ** nat_chains, int prerouting, mdd_handle & outputMDD,
               mdd_handle & logMDD);
