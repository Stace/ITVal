/*
 * ITVal: The IPTables Firewall Validator Copyright (C) 2004 Robert
 * Marmorstein
 * 
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. A full-text
 * version is located in the LICENSE file distributed with this utility.
 * 
 * You may contact the author at rmmarm@wm.edu or by sending mail to:
 * 
 * Robert Marmorstein Department of Computer Science College of William
 * and Mary Williamsburg, VA 23185 
 */

#include "chains.h"
#include "rules.h"

// Some useful Print functions for debugging

// Print a range of addresses
void PrintRange(address_range * ar)
{
   address_range *cur;

   cur = ar;
   while (cur != NULL) {
      printf("%u to %u\n", cur->low, cur->high);
      cur = cur->next;
   }
}

// Unprocessed Rules
void PrintRule(rule newRule)
{
   printf("Id: %d\n", newRule.id);
   printf("Target: %s\n", newRule.target);
   printf("Protocol: %s\n", newRule.protocol);
   printf("Opt: %s\n", newRule.opt);
   printf("Source: %s\n", newRule.source);
   printf("Destination: %s\n", newRule.dest);
   printf("Info: %s\n", newRule.info);
}

// Chains
void PrintChain(chain * c)
{
   rule *r;

   if (c == NULL) {
      printf("Null chain.\n");
      return;
   }
   printf("%s chain.\n", c->name);
   r = c->rules;
   while (r) {
      PrintRule(*r);
      r = r->next;
   }
}

// Processed Rules
void PrintProcessedRule(processed_rule * r)
{
   port_range *cur;

   if (r == NULL)
      return;
   printf("From: ");
   PrintRange(r->from);
   printf("To: ");
   PrintRange(r->to);
   printf("Protocol: %c\nState: %d\n", r->protocol, r->state);
   printf("Target: %s\n", r->target);
   printf("Source Ports: ");
   cur = r->sports;
   while (cur) {
      printf("%d ", cur->port1 * 256 + cur->port2);
      cur = cur->next;
   }
   printf("\n");
   printf("Dest Ports: ");
   cur = r->dports;
   while (cur) {
      printf("%d ", cur->port1 * 256 + cur->port2);
      cur = cur->next;
   }
   printf("\n");
   printf("----------------\n");
}

// Processed NAT Rules
void PrintProcessedNATRule(processed_nat_rule * r)
{
   port_range *cur;

   if (r == NULL)
      return;
   printf("From: ");
   PrintRange(r->from);
   printf("To: ");
   PrintRange(r->to);
   printf("Protocol: %c\nState: %d\n", r->protocol, r->state);
   printf("Target: %s\n", r->target);
   printf("Source Ports: ");
   cur = r->sports;
   while (cur) {
      printf("%d ", cur->port1 * 256 + cur->port2);
      cur = cur->next;
   }
   printf("\n");
   printf("Dest Ports: ");
   cur = r->dports;
   while (cur) {
      printf("%d ", cur->port1 * 256 + cur->port2);
      cur = cur->next;
   }
   printf("\n");
   if (r->nat) {
      printf("NAT Addy: ");
      PrintRange(&r->nat->addys);
      printf("NAT Ports: ");
      printf("%d ", r->nat->ports.port1);
      printf("%d ", r->nat->ports.port2);
      cur = r->nat->ports.next;
      while (cur) {
         printf("%d %d", cur->port1, cur->port2);
         cur = cur->next;
      }
   }
   printf("----------------\n");
}

// Rule Tuples
void PrintRuleTuple(rule_tuple * r)
{
   int i;

   printf("Chain %d, Rule %d --> ", r->chain_id, r->id);
   for (i = 22; i >= 0; i--) {
      printf("%d-%d ", r->low[i], r->high[i]);
   }
   printf("\n");
}
