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
//#define STACK_DEBUG
#define RULE_QUERY_DEBUG

#include "iface.h"
#include "firewall.h"

#include "debug.h"

#define MAX(x,y) ((x)>(y) ? (x) : (y))
#define MIN(x,y) ((x)<(y) ? (x) : (y))

/*
 * The following functions, taken together, turn a processed_rule, pr, into
 * a set of rule_tuples suitable for insertion into an MDD.  The
 * resulting tuples are stored on a stack, which is passed as a reference
 * parameter.
 *
 * The current tuple is stored in "tup".  Starting with "ProcessSource",
 * each function sets some elements of tup.  Then, tup is handed to
 * another function in which sets some more elements.  
 * When all elements have been filled, the last function, ProcessTarget,
 * pushes "tup" onto the stack.
 */

/*
 * Store the target of "pr" as tup[0] and push onto the stack.
 */

void
  Firewall::ProcessTarget(processed_rule * pr, rule_tuple * tup,
                          rule_tuple * &stack)
{
   rule_tuple *newTup;
   int val;

   /*
    * If it's a "LOG" mark it specially, so that it can be put in the
    * Log MDD instead of the ACCEPT MDD.
    */
   if (strncmp(pr->target, "LOG", 3) == 0) {
      tup->low[0] = tup->high[0] = LOG;
   }
   else if (strncmp(pr->target, "RETURN", 6) == 0) {
      tup->low[0] = tup->high[0] = RETURN;
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
   else {
      // If it's not LOG, ACCEPT, DROP, REJECT, NETMAP, MASQUERADE, or REDIRECT, 
      // it must be a user-defined chain.  We add NUM_DEFAULT_TARGETS
      // to distinguish it from the builtin targets.
      val = FindChain(pr->target);

      //If it's a special target not handled by ITVal (TCPMSS, i.e.)
      if (val == -2)
         return;

      if (val < 0) {
         printf("Could not find target: %s\n", pr->target);
         assert(0);
      }
      tup->low[0] = tup->high[0] = val + NUM_DEFAULT_TARGETS;
   }

   // Now push the tuple onto the stack.
   newTup = new rule_tuple;
   newTup->id = pr->id;
   newTup->chain_id = pr->chain_id;
#ifdef STACK_DEBUG
printf("On Stack:\n");
for (int i=22;i>=0;i--){
   printf("%d-%d ", tup->low[i], tup->high[i]);
}
printf("\n");
#endif
   for (int i = 0; i < 23; i++) {
      newTup->low[i] = tup->low[i];
      newTup->high[i] = tup->high[i];
   }
   newTup->next = stack;
   stack = newTup;

   //printf("Rule:\n");
   //PrintRuleTuple(stack);
}

/*
 * Store values of TCP flags FIN, SYN, RST, PSH, ACK, and URG in tup[1]
 * through tup[6].
 */

void Firewall::ProcessFlags(processed_rule * pr, rule_tuple * tup,
                            rule_tuple * &stack)
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
   ProcessTarget(pr, tup, stack);
}

/*
 * Store information about state in the tuple.
 */

void Firewall::ProcessState(processed_rule * pr, rule_tuple * tup,
                            rule_tuple * &stack)
{
   int state = pr->state;

   if (state == 0) {
      // 0 means any state.
      tup->low[7] = 0;
      tup->high[7] = 3;
      ProcessFlags(pr, tup, stack);
   }
   if (state & INVALID) {
      tup->low[7] = tup->high[7] = 0;
      ProcessFlags(pr, tup, stack);
   }
   if (state & NEW) {
      tup->low[7] = tup->high[7] = 1;
      ProcessFlags(pr, tup, stack);
   }
   if (state & ESTABLISHED) {
      tup->low[7] = tup->high[7] = 2;
      ProcessFlags(pr, tup, stack);
   }
   if (state & RELATED) {
      tup->low[7] = tup->high[7] = 3;
      ProcessFlags(pr, tup, stack);
   }
}

void Firewall::ProcessIfaces(processed_rule * pr, rule_tuple * tup,
                             rule_tuple * &stack)
{
   if (pr->in >= 0)
      tup->low[9] = tup->high[9] = pr->in;
   else {
      tup->low[9] = 0;
      tup->high[9] = 255;
   }

   if (pr->out >= 0)
      tup->low[8] = tup->high[8] = pr->out;
   else {
      tup->low[8] = 0;
      tup->high[8] = 255;
   }

   ProcessState(pr, tup, stack);
}

/*
 * Store the destination port in the tuple.  The port is partitioned
 * into two bytes, to improve performance of the MDD.  Since
 * processed_rules can contain multiple port_ranges in a linked list,
 * we can actually generate several tuples here instead of just one.
 */

void Firewall::ProcessDport(processed_rule * pr, rule_tuple * tup,
                            rule_tuple * &stack)
{
   port_range *cur;

   cur = pr->dports;
   if (cur == NULL) {
      // If no destination port is specified, any port matches.
      tup->low[11] = 0;
      tup->high[11] = 255;
      tup->low[10] = 0;
      tup->high[10] = 255;
      ProcessIfaces(pr, tup, stack);
   }
   else {
      // Loop across the linked list to handle multiple port ranges.
      while (cur != NULL) {
         tup->low[11] = tup->high[11] = cur->port1;
         tup->low[10] = tup->high[10] = cur->port2;
         ProcessIfaces(pr, tup, stack);
         cur = cur->next;
      }
   }
}

/*
 * Store the source port information in the tuple.  Just like
 * ProcessDport, we may push several tuples onto the stack if 
 * pr has multiple port_ranges.
 */

void Firewall::ProcessSport(processed_rule * pr, rule_tuple * tup,
                            rule_tuple * &stack)
{
   port_range *cur;

   cur = pr->sports;
   if (cur == NULL) {
      // If not specified in the rule, any port matches.
      tup->low[13] = 0;
      tup->high[13] = 255;
      tup->low[12] = 0;
      tup->high[12] = 255;
      ProcessDport(pr, tup, stack);
   }
   else {
      // Loop across the linked list to handle multiple port ranges.
      while (cur != NULL) {
         tup->low[13] = tup->high[13] = cur->port1;
         tup->low[12] = tup->high[12] = cur->port2;
         ProcessDport(pr, tup, stack);
         cur = cur->next;
      }
   }
}

/*
 * Store the protocol information in the tuple.  Supported protocols are
 * ICMP, UDP, and TCP.
 */

void Firewall::ProcessProt(processed_rule * pr, rule_tuple * tup,
                           rule_tuple * &stack)
{
   switch (pr->protocol) {
      case 'i':
         tup->low[14] = tup->high[14] = ICMP;   // icmp
         break;
      case 'u':
         tup->low[14] = tup->high[14] = UDP;    // udp
         break;
      case 't':
         tup->low[14] = tup->high[14] = TCP;    // tcp
         break;
      default:
         // If it's 'a', any protocol matches.
         tup->low[14] = 0;
         tup->high[14] = 2;
         break;
   }
   ProcessSport(pr, tup, stack);
}

void Firewall::ProcessInverseSource(address_range * cur, processed_rule * pr, rule_tuple *
tup, rule_tuple * &stack){
   int i;
   if (cur->mask == 0)  //Inverse of everything is nothing!
      return;
   if (cur->mask == 32){
      for (i=0;i<4;i++){
         int j;
         for (j=i+1;j<4;j++){
            tup->low[22-j] = 0;
            tup->high[22-j] = 255;
         }
         tup->low[22-i] = 0;
         tup->high[22-i] = cur->low[i]-1;
         if (tup->low[22-i]<=tup->high[22-i])
            ProcessDest(pr,tup,stack);
         tup->low[22-i] = cur->high[i]+1;
         tup->high[22-i] = 255;
         if (tup->low[22-i]<=tup->high[22-i])
            ProcessDest(pr,tup,stack);
         tup->low[22-i] = cur->low[i];
         tup->high[22-i] = cur->high[i];
      }
      return;
   }
   for (i=0;i<=cur->mask/8;i++){
      int j;
      for (j=i+1;j<4;j++){
         tup->low[22-j] = 0;
         tup->high[22-j] = 255;
      }
      tup->low[22-i] = 0;
      tup->high[22-i] = cur->low[i]-1;
      if (tup->low[22-i]<=tup->high[22-i])
         ProcessDest(pr,tup,stack);
      tup->low[22-i] = cur->high[i]+1;
      tup->high[22-i] = 255;
      if (tup->low[22-i]<=tup->high[22-i])
         ProcessDest(pr,tup,stack);
      tup->low[22-i] = cur->low[i];
      tup->high[22-i] = cur->high[i];
   }
}

void Firewall::ProcessInverseDest(address_range * cur, processed_rule * pr, rule_tuple *
tup, rule_tuple * &stack){
   int i;
   if (cur->mask == 0)  //Inverse of everything is nothing!
      return;
   if (cur->mask == 32){
      for (i=0;i<4;i++){
         int j;
         for (j=i+1;j<4;j++){
            tup->low[18-j] = 0;
            tup->high[18-j] = 255;
         }
         tup->low[18-i] = 0;
         tup->high[18-i] = cur->low[i]-1;
         if (tup->low[18-i]<=tup->high[18-i])
            ProcessProt(pr,tup,stack);
         tup->low[18-i] = cur->high[i]+1;
         tup->high[18-i] = 255;
         if (tup->low[18-i]<=tup->high[18-i])
            ProcessProt(pr,tup,stack);
         tup->low[18-i] = cur->low[i];
         tup->high[18-i] = cur->high[i];
      }
      return;
   }
   for (i=0;i<=cur->mask/8;i++){
      int j;
      for (j=i+1;j<4;j++){
         tup->low[18-j] = 0;
         tup->high[18-j] = 255;
      }
      tup->low[18-i] = 0;
      tup->high[18-i] = cur->low[i]-1;
      if (tup->low[18-i]<=tup->high[18-i])
         ProcessProt(pr,tup,stack);
      tup->low[18-i] = cur->high[i]+1;
      tup->high[18-i] = 255;
      if (tup->low[18-i]<=tup->high[18-i])
         ProcessProt(pr,tup,stack);
      tup->low[18-i] = cur->low[i];
      tup->high[18-i] = cur->high[i];
   }
}

/*
 * Store the destination address information in the tuple.  IP addresses
 * are partitioned into four bytes to improve performance of the MDD.  
 * (Partitioning also helps readability when debugging).
 */

void Firewall::ProcessDest(processed_rule * pr, rule_tuple * tup,
                           rule_tuple * &stack)
{
   address_range * cur;
   cur = pr->to;
   while (cur != NULL){
      int i;
      if (!cur->invert){
         for (i=0;i<4;i++){
            tup->low[18-i] = cur->low[i];
            tup->high[18-i] = cur->high[i];
         }
         ProcessProt(pr, tup, stack);
      }
      else{
         ProcessInverseDest(cur,pr, tup, stack);
      }
      cur = cur->next;
   }
}

/*
 * Store the destination address information in the tuple.  IP addresses
 * are partitioned into four bytes to improve performance of the MDD.  
 * (Partitioning also helps readability when debugging).
 */

void Firewall::ProcessSource(processed_rule * pr, rule_tuple * tup,
                           rule_tuple * &stack)
{
   address_range * cur;
   cur = pr->from;
   while (cur != NULL){
      int i;
      if (!cur->invert){
         for (i=0;i<4;i++){
            tup->low[22-i] = cur->low[i];
            tup->high[22-i] = cur->high[i];
         }
         ProcessDest(pr, tup, stack);
      }
      else{
         ProcessInverseSource(cur, pr, tup , stack);
      }
      cur = cur->next;
   }
}

/*
 * In reverse order(to preserve the IP tables semantics), turn a linked
 * list of processed_rules beginning with "head" into a stack of tuples 
 * suitable for insertion into the MDD.
 */

void Firewall::BuildRules(processed_rule * head, rule_tuple * &stack)
{
   rule_tuple *tup;                       // A placeholder output tuple

   if (head == NULL)            // If the list is empty, we're done.
      return;

   tup = new rule_tuple;
   BuildRules(head->next, stack);       // In Reverse order.
#ifdef STACK_DEBUG
   printf("Processing Chain: %d Rule: %d\n", head->chain_id, head->id); 
#endif
   if (head->pktcond <=1)               // Temporarily, ignore PKTTYPE flags.
      ProcessSource(head, tup, stack);     // Initiate the processing chain.
#ifdef RULE_QUERY_DEBUG
    printf("Building rule tuples:\n");
    if (stack==NULL){
       printf("No rules.\n");
    }
    else{
       PrintRuleTuple(stack);
    }
    printf("Done building rule tuples.\n");
#endif
   delete tup;
}

// Turn a stack of rule_tuples into an MDD describing the set of accepted
// packets and an MDD describing the set of logged packets.

// Tuples that point to another chain are "intersected" with the MDD for
// that chain until their final fate becomes clear.  Then, they are
// inserted into outMDD.  This confusing recursive algorithm is
// the guts of this tool.

// chain_array is the array of iptables chains.  inMDD is an MDD
// representing the tuples in the chain that have already been processed.
// "tup" is the tuple to be inserted.  outMDD and logMDD are the outputs
// of the function.


void Firewall::ProcessChain(chain ** chain_array, mdd_handle inMDD, mdd_handle
      inHistMDD, rule_tuple * tup, mdd_handle & outMDD, mdd_handle & logMDD,
      mdd_handle & outHistMDD){
 
   // criteriaMDD represents the set of packets that match the tuple.
   mdd_handle criteriaMDD;

   //Matches tuples to the chain/rule pairs that match each tuple.
   mdd_handle historyMDD;

   // We process the rules of the chain in reverse order to preserve IP
   // tables semantics.
    
   if (tup == NULL) {
      // If we've gotten past the last chain, we just copy the inputMDD
      // and return.
      FWForest->Attach(outMDD, inMDD.index);
#ifndef NO_HISTORY
      HistoryForest->Attach(outHistMDD, inHistMDD.index);
#endif
      return;
   }

   //Recurse down the stack (To reverse the order)
   ProcessChain(chain_array, inMDD, inHistMDD, tup->next, 
	 outMDD, logMDD, outHistMDD);


   // If it's a log rule, insert it into the Log MDD and continue processing.

   if (tup->high[0] == -1) {
      tup->low[0] = tup->high[0] = 1;
      FWForest->Assign(logMDD, tup->low, tup->high, logMDD);
      tup->low[0] = tup->high[0] = -1;

//      tup->hlow[2] = tup->hhigh[2] = tup->chain_id; 
//      tup->hlow[1] = tup->hhigh[1] = tup->id;  
//      tup->hlow[0] = tup->hhigh[0] = 1;
//      HistoryForest->Assign(outHistMDD, tup->hlow, tup->hhigh, outHistMDD);

      return;
   }

   // Otherwise, take the output of the previous function off the stack
   // and make it the input MDD.

//   FWForest->DestroyMDD(inMDD); //bad?
//   HistoryForest->DestroyMDD(inHistMDD); //bad?

   if (inMDD.index != outMDD.index){
      FWForest->Attach(inMDD, outMDD.index);
   }

#ifndef NO_HISTORY
   if (inHistMDD.index != outHistMDD.index){
//      HistoryForest->ReallocHandle(inHistMDD);
      HistoryForest->Attach(inHistMDD, outHistMDD.index);
   }
#endif

   // Create the intermediate MDDs
   for (int k=22;k>=0;k--){
      tup->hlow[k+2] = tup->low[k];
      tup->hhigh[k+2] = tup->high[k];
   } 
   tup->hlow[2] = tup->hhigh[2] = tup->chain_id; 
   tup->hlow[1] = tup->hhigh[1] = tup->id;  

   //assert(tup->low[0] >= 0);
   //assert(tup->high[0] >= 0);

   tup->hlow[0] = tup->low[0];
   tup->hhigh[0] = tup->high[0];
   
   // If the rule is a terminating rule (ACCEPT, DROP, OR REJECT)
   // We simply insert it into the MDD.

   if (tup->low[0] < NUM_DEFAULT_TARGETS) {
      // Insert it into the MDD.  Replace takes a flag
      // parameter that indicates whether to insert new
      // tuples.  When passed "true" it copies the tuples in
      // interMDD into inMDD whether they already have values
      // or not.  The result is stored in outMDD.

//      FWForest->Replace(inMDD, criteriaMDD, true, outMDD);
      for (int k=22;k>=0;k--){
         tup->hlow[k+2] = tup->low[k];
         tup->hhigh[k+2] = tup->high[k];
      } 
      tup->hlow[2] = tup->hhigh[2] = tup->chain_id; 
      tup->hlow[1] = tup->hhigh[1] = tup->id;  

//      assert(tup->low[0] >= 0);
//      assert(tup->high[0] >= 0);

      tup->hlow[0] = tup->low[0];
      tup->hhigh[0] = tup->high[0];
#ifdef STACK_DEBUG
      printf("B: Chain %d, Rule %d: MDD %d\n", tup->chain_id, tup->id, outMDD.index);
      FWForest->PrintMDD();
#endif
      FWForest->Assign(inMDD, tup->low, tup->high, outMDD);
#ifdef STACK_DEBUG
      printf("A: Chain %d, Rule %d: MDD %d\n", tup->chain_id, tup->id, outMDD.index);
      FWForest->PrintMDD();
#endif
      //Union the input MDD with the intermediate and store in "outHistMDD".
      //HistoryForest->Max(inHistMDD, historyMDD, outHistMDD);

#ifndef NO_HISTORY
      //Actually, just assign, since we're interested in the 'critical rule'.
      HistoryForest->Assign(inHistMDD, tup->hlow, tup->hhigh, outHistMDD);
#endif
      // Since we are doing things in reverse order, it's possible
      // that a packet that matches a log rule later in the chain 
      // has already been inserted into logMDD, but can't get there
      // because we dropped or accepted it.  So, we erase it from the
      // log right here.
      int oldTarget;
      oldTarget = tup->low[0];
      tup->low[0] = tup->high[0] = 0;
      FWForest->Assign(logMDD, tup->low, tup->high, logMDD);

      // Restore the tuple in case it is reachable through another chain.
      tup->low[0] = tup->high[0] = oldTarget;  
   }
   else {
      // If the target is another chain, we have to construct the other
      // chain first.  But only that PART of the chain which matches
      // the tuple we're working on (otherwise, loops are an issue).  So . . .

      chain *nextChain;  // The target chain of the current rule.

      nextChain = chain_array[tup->low[0] - NUM_DEFAULT_TARGETS];

      mdd_handle targetMDD;
      mdd_handle targetHistMDD;

      ProcessChain(chain_array, inMDD, inHistMDD, nextChain->tup, targetMDD,
	    logMDD, targetHistMDD);

      mdd_handle resultMDD;
      mdd_handle resultHistMDD;
   
      FWForest->MakeMDDFromTuple(tup->low, tup->high, criteriaMDD);
      
#ifndef NO_HISTORY
      HistoryForest->MakeMDDFromTuple(tup->hlow, tup->hhigh, historyMDD);
#endif

      FWForest->ProjectOnto(targetMDD, criteriaMDD, resultMDD);
      
#ifndef NO_HISTORY
      HistoryForest->ProjectOnto(targetHistMDD, historyMDD, resultHistMDD);
#endif

      // Clean up criteriaMDD.
      FWForest->DestroyMDD(criteriaMDD);
      
#ifndef NO_HISTORY
      HistoryForest->DestroyMDD(historyMDD);
#endif

      //Any rule in the new chain that affects the packet needs to be counted
      //now.  

      FWForest->Replace(inMDD, resultMDD, true, outMDD);
      //HistoryForest->Max(inHistMDD, resultHistMDD, outHistMDD); 
      //Is this correct?@@@@
      
#ifndef NO_HISTORY
      HistoryForest->Replace(inHistMDD, resultHistMDD, true, outHistMDD); //Is this correct?@@@@
#endif
      FWForest->DestroyMDD(resultMDD);
#ifndef NO_HISTORY
      HistoryForest->DestroyMDD(resultHistMDD);
#endif
      FWForest->DestroyMDD(targetMDD);
#ifndef NO_HISTORY
      HistoryForest->DestroyMDD(targetHistMDD);
#endif
   }
   /*
   for (level k = 24; k > 0; k--)
      HistoryForest->Compact(k);

   for (level k = 22; k > 0; k--)
      FWForest->Compact(k);
   */
}

// Initiate construction of outMDD and logMDD.
void Firewall::AssembleChains(chain ** chain_array, chain * chain,
                              mdd_handle & outMDD, mdd_handle & logMDD, mdd_handle & outHistMDD)
{
   // Here we set the default policy for the builtin chain.

   mdd_handle initMDD;
   mdd_handle initHistMDD;

   int low[23], hlow[25];
   int high[23], hhigh[25];

   low[0] = high[0] = chain->Default;   // Set default policy
   low[1] = 0;
   high[1] = 1;                 // Any value for FIN flag
   low[2] = 0;
   high[2] = 1;                 // SYN flag
   low[3] = 0;
   high[3] = 1;                 // RST flag
   low[4] = 0;
   high[4] = 1;                 // PSH flag
   low[5] = 0;
   high[5] = 1;                 // ACK flag
   low[6] = 0;
   high[6] = 1;                 // URG flag
   low[7] = 0;
   high[7] = 3;                 // Any state
   low[8] = 0;
   high[8] = 255;               // Any Output Interface
   low[9] = 0;
   high[9] = 255;               // Any Input Interface
   low[10] = 0;

   high[10] = 255;              // Any destination port
   low[11] = 0;
   high[11] = 255;
   low[12] = 0;

   high[12] = 255;              // Any source port
   low[13] = 0;
   high[13] = 255;
   low[14] = 0;

   high[14] = 2;                // Any Protocol
   low[15] = 0;

   high[15] = 255;              // Any destination IP
   low[16] = 0;
   high[16] = 255;
   low[17] = 0;
   high[17] = 255;
   low[18] = 0;
   high[18] = 255;
   low[19] = 0;

   high[19] = 255;              // Any source IP
   low[20] = 0;
   high[20] = 255;
   low[21] = 0;
   high[21] = 255;
   low[22] = 0;
   high[22] = 255;


   for (int i=0;i<=22;i++){
      hhigh[i+2] = high[i];
      hlow[i+2] = low[i];
   }
//   hlow[0] = 1;
//   hhigh[0] = 1;
   hlow[0] = hhigh[0] = chain->Default;

   hlow[1] = 0;   //Default Policy is rule 0.
   hhigh[1] = 0;

   hlow[2] = chain->id;
   hhigh[2] = chain->id;

   // Create an MDD representing the default policy
   FWForest->MakeMDDFromTuple(low, high, initMDD);
#ifndef NO_HISTORY
   HistoryForest->MakeMDDFromTuple(hlow, hhigh, initHistMDD);
#endif

   // It becomes the initial "inMDD" to ProcessChain.
   if (chain->tup != NULL) {
      ProcessChain(chain_array, initMDD, initHistMDD, chain->tup, outMDD, logMDD, outHistMDD);
      FWForest->DestroyMDD(initMDD);
#ifndef NO_HISTORY
      HistoryForest->DestroyMDD(initHistMDD);
#endif
   }
   else {
      FWForest->Attach(outMDD, initMDD.index);
#ifndef NO_HISTORY
      HistoryForest->Attach(outHistMDD, initHistMDD.index);
#endif
   }
}
