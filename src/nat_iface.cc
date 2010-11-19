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

#include "iface.h"
#include "debug.h"
#include "firewall.h"
#include <assert.h>

void Firewall::DoNAT(nat_tuple * tup, mdd_handle inMDD, mdd_handle inHistMDD,
      mdd_handle & outMDD, mdd_handle & logMDD, mdd_handle & outHistMDD) {

   mdd_handle interMDD;
   mdd_handle interHistMDD;
//   int hlow[25];
//   int hhigh[25];

   if (tup == NULL)
      return;
   DoNAT((nat_tuple *) tup->next, inMDD, inHistMDD, outMDD, logMDD, outHistMDD);

   if (tup->low[0] == DNAT) {
      // NAT rule
      FWForest->DNAT(inMDD, tup, outMDD);
      HistoryForest->DNAT(inHistMDD, tup, outHistMDD);
      FWForest->DNAT(logMDD, tup, logMDD);
   }
   else if (tup->low[0] == REDIRECT) {
//      FWForest->DNAT(inMDD, tup, outMDD);
//      HistoryForest->DNAT(inHistMDD, tup, outHistMDD);
//      FWForest->DNAT(logMDD, tup, logMDD);
   }
   else if (tup->low[0] == SNAT) {
      FWForest->SNAT(inMDD, tup, outMDD);
      HistoryForest->SNAT(inHistMDD, tup, outHistMDD);
      FWForest->SNAT(logMDD, tup, logMDD);
   }
   else if(tup->low[0] == MASQUERADE){
//      FWForest->SNAT(inMDD, tup, outMDD);
//      HistoryForest->SNAT(inHistMDD, tup, outHistMDD);
//      FWForest->SNAT(logMDD, tup, logMDD);
   }
   else if (tup->low[0] == NETMAP) {
      FWForest->NETMAP(inMDD, tup, outMDD);
      HistoryForest->NETMAP(inHistMDD, tup, outHistMDD);
      FWForest->NETMAP(logMDD, tup, logMDD);
   }
   else if (tup->low[0] == ACCEPT || tup->low[0] == DROP
            || tup->low[0] == REJECT) {
      // If it was an ACCEPT or DROP rule

      // Insert it into the MDD.
      FWForest->MakeMDDFromTuple(tup->low, tup->high, interMDD);

      for (int i=0;i<=22;i++){
         tup->hlow[i+2]=tup->low[i];
         tup->hhigh[i+2]=tup->high[i];
      }
      tup->hlow[2] = tup->hhigh[2] = tup->chain_id;
      tup->hlow[1] = tup->hhigh[1] = tup->id;
//      tup->hlow[0] = tup->hhigh[0] = 1;
      tup->hlow[0] = tup->low[0];
      tup->hhigh[0] = tup->high[0];
      HistoryForest->MakeMDDFromTuple(tup->hlow, tup->hhigh, interHistMDD);

      FWForest->Replace(inMDD, interMDD, true, outMDD);
      HistoryForest->Replace(inHistMDD, interHistMDD, true, outHistMDD);
      FWForest->DestroyMDD(interMDD);
      HistoryForest->DestroyMDD(interHistMDD);

      // Remove it from the LOG
      tup->low[0] = tup->high[0] = 0;
      FWForest->Assign(logMDD, tup->low, tup->high, logMDD);
   }
   else {
      printf("Bad target in NAT.\n");
      assert(0);
   }
}

void Firewall::NATChains(int chain_num, mdd_handle inMDD, mdd_handle inHistMDD, mdd_handle & outMDD, mdd_handle & logMDD, mdd_handle & outHistMDD)
{
   nat_tuple *stack;

   stack = NULL;
   ConvertNATRules(nat_chains[chain_num]->natRules, stack);
   DoNAT(stack, inMDD, inHistMDD, outMDD, logMDD, outHistMDD); // To reverse the order
}

void Firewall::ProcessNATTarget(processed_nat_rule * pr, nat_tuple * tup,
                                nat_tuple * &stack)
{
   nat_tuple *newTup;
   int val;

   // If it's a "LOG" mark it specially, so that it can be put in the
   // Log MDD instead of the ACCEPT MDD.
   if (strncmp(pr->target, "LOG", 3) == 0) {
      tup->low[0] = tup->high[0] = LOG;
   }
   else if (strncmp(pr->target, "ACCEPT", 6) == 0) {
      tup->low[0] = tup->high[0] = ACCEPT;
   }
   else if (strncmp(pr->target, "REJECT", 6) == 0) {    // If it's a
      // "REJECT" 
      tup->low[0] = tup->high[0] = REJECT;
   }
   else if (strncmp(pr->target, "DROP", 4) == 0) {      // If it's a drop.
      tup->low[0] = tup->high[0] = DROP;
   }
   else if (strncmp(pr->target, "DNAT", 4) == 0) {      // If it's a NAT.
      tup->low[0] = tup->high[0] = DNAT;
   }
   else if (strncmp(pr->target, "NETMAP", 6) == 0) {    // If it's a NETMAP.
      tup->low[0] = tup->high[0] = NETMAP;
   }
   else if (strncmp(pr->target, "MASQUERADE", 10) == 0) {// If MASQUERADE.
	tup->low[0] = tup->high[0] = MASQUERADE;
   }
   else if (strncmp(pr->target, "REDIRECT", 8) == 0) {// If REDIRECT.
	tup->low[0] = tup->high[0] = REDIRECT;
   }
   else {
      // If it's not LOG, ACCEPT, DROP, REJECT, DNAT, or NETMAP, 
      // MASQUERADE, or REDIRECT, it must be a user-defined chain.  
      // We add 4 to distinguish it from the builtin targets.
      val = FindNATChain(pr->target);
      if (val < 0) {
         printf("Couldn't find chain: %s\n", pr->target);
         assert(0);
      }
      tup->low[0] = tup->high[0] = val + 4;
   }
   // Now push the tuple onto the stack.
   newTup = new nat_tuple;
   for (int i = 0; i <= 20; i++) {
      newTup->low[i] = tup->low[i];
      newTup->high[i] = tup->high[i];
   }
   newTup->nat = pr->nat;
   newTup->next = stack;
   stack = newTup;
}

// Store values of TCP flags FIN, SYN, RST, PSH, ACK, and URG in tup[1]
// through tup[6].
void Firewall::ProcessNATFlags(processed_nat_rule * pr, nat_tuple * tup,
                               nat_tuple * &stack)
{
   int i;

   for (i = 0; i < 6; i++) {
      // -1 means the flag is not specified in the rule.  So packets
      // matching either 0 or 1 are acceptable.

      if (pr->flags[i] == -1) {
         tup->low[6 - i] = 0;
         tup->high[6 - i] = 1;
      }
      else {
         tup->low[6 - i] = tup->high[6 - i] = pr->flags[i];
      }
   }
   ProcessNATTarget(pr, tup, stack);
}

// Store information about state in the tuple.
void Firewall::ProcessNATState(processed_nat_rule * pr, nat_tuple * tup,
                               nat_tuple * &stack)
{
   int state = pr->state;

   if (state == 0) {
      // 0 means any state.
      tup->low[7] = 0;
      tup->high[7] = 4;
      ProcessNATFlags(pr, tup, stack);
   }
   if (state & INVALID) {
      tup->low[7] = tup->high[7] = 0;
      ProcessNATFlags(pr, tup, stack);
   }
   if (state & NEW) {
      tup->low[7] = tup->high[7] = 1;
      ProcessNATFlags(pr, tup, stack);
   }
   if (state & ESTABLISHED) {
      tup->low[7] = tup->high[7] = 2;
      ProcessNATFlags(pr, tup, stack);
   }
   if (state & RELATED) {
      tup->low[7] = tup->high[7] = 3;
      ProcessNATFlags(pr, tup, stack);
   }
}

// Store the destination port in the tuple.  The port is partitioned
// into two bytes, to improve performance of the MDD.  Since
// processed_nat_rules can contain multiple port_ranges in a linked list,
// we can actually generate several tuples here instead of just one.
void Firewall::ProcessNATDport(processed_nat_rule * pr, nat_tuple * tup,
                               nat_tuple * &stack)
{
   port_range *cur;

   cur = pr->dports;
   if (cur == NULL) {
      // If no destination port is specified, any port matches.
      tup->low[9] = 0;
      tup->high[9] = 255;
      tup->low[8] = 0;
      tup->high[8] = 255;
      ProcessNATState(pr, tup, stack);
   }
   else {
      // Loop across the linked list to handle multiple port ranges.
      while (cur != NULL) {
         tup->low[9] = tup->high[9] = cur->port1;
         tup->low[8] = tup->high[8] = cur->port2;
         ProcessNATState(pr, tup, stack);
         cur = cur->next;
      }
   }
}

// Store the source port information in the tuple.  Just like
// ProcessDport, we may push several tuples onto the stack if 
// pr has multiple port_ranges.
void Firewall::ProcessNATSport(processed_nat_rule * pr, nat_tuple * tup,
                               nat_tuple * &stack)
{
   port_range *cur;

   cur = pr->sports;
   if (cur == NULL) {
      // If not specified in the rule, any port matches.
      tup->low[11] = 0;
      tup->high[11] = 255;
      tup->low[10] = 0;
      tup->high[10] = 255;
      ProcessNATDport(pr, tup, stack);
   }
   else {
      // Loop across the linked list to handle multiple port ranges.
      while (cur != NULL) {
         tup->low[11] = tup->high[11] = cur->port1;
         tup->low[10] = tup->high[10] = cur->port2;
         ProcessNATDport(pr, tup, stack);
         cur = cur->next;
      }
   }
}

// Store the protocol information in the tuple.  Supported protocols are
// ICMP, UDP, and TCP

void Firewall::ProcessNATProt(processed_nat_rule * pr, nat_tuple * tup,
                              nat_tuple * &stack)
{
   switch (pr->protocol) {
      case 'i':
         tup->low[12] = tup->high[12] = ICMP;   // icmp
         break;
      case 'u':
         tup->low[12] = tup->high[12] = UDP;    // udp
         break;
      case 't':
         tup->low[12] = tup->high[12] = TCP;    // tcp
         break;
      default:
         // If it's 'a', any protocol matches.
         tup->low[12] = 0;
         tup->high[12] = 2;
         break;
   }
   ProcessNATSport(pr, tup, stack);
}

// Store the destination address information in the tuple.  IP addresses
// are partitioned into four bytes to improve performance of the MDD.  
// (Partitioning also helps readability when debugging).
void Firewall::ProcessNATDest(processed_nat_rule * pr, nat_tuple * tup,
                              nat_tuple * &stack)
{
   tup->low[13] = pr->to->low[3];
   tup->low[14] = pr->to->low[2];
   tup->low[15] = pr->to->low[1];
   tup->low[16] = pr->to->low[0];
   tup->high[13] = pr->to->high[3];
   tup->high[14] = pr->to->high[2];
   tup->high[15] = pr->to->high[1];
   tup->high[16] = pr->to->high[0];
   ProcessNATProt(pr, tup, stack);
}

// Store the source address information in the tuple.  As in
// ProcessNATDest,
// IP addresses are partitioned into four bytes.
void Firewall::ProcessNATSource(processed_nat_rule * pr, nat_tuple * tup,
                                nat_tuple * &stack)
{
   tup->low[17] = pr->from->low[3];
   tup->low[18] = pr->from->low[2]; 
   tup->low[19] = pr->from->low[1]; 
   tup->low[20] = pr->from->low[0]; 
   tup->high[17] = pr->from->high[3];
   tup->high[18] = pr->from->high[2];
   tup->high[19] = pr->from->high[1];
   tup->high[20] = pr->from->high[0];
     
   ProcessNATDest(pr, tup, stack);
}

// In reverse order(to preserve the IP tables semantics), turn a linked
// list of processed_nat_rules beginning with "head" into a stack of
// tuples suitable for modifying the filter MDD.

void Firewall::ConvertNATRules(processed_nat_rule * head, nat_tuple * &stack)
{
   nat_tuple *tup;                        // A placeholder output tuple

   if (head == NULL)            // If the list is empty, we're done.
      return;

   ConvertNATRules((processed_nat_rule *) head->next, stack);   // In
   // Reverse 
   // order.
   tup = new nat_tuple;
   ProcessNATSource(head, tup, stack);  // Initiate the processing chain.
   delete tup;
}
