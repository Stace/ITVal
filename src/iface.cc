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
//#define BUILD_DEBUG
//#define STACK_DEBUG
//#define RULE_QUERY_DEBUG

#include "iface.h"
#include "firewall.h"

//#include "debug.h"

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
   newTup->fw_id = pr->fw_id;
   strncpy(newTup->text, pr->text, 2048);
#ifdef STACK_DEBUG
printf("On Stack:\n");
for (int i=TOP_LEVEL;i>=0;i--){
   printf("%d-%d ", tup->low[i], tup->high[i]);
}
printf("\n");
#endif
   for (int i = 0; i <= TOP_LEVEL; i++) {
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
            tup->low[TOP_LEVEL-j] = 0;
            tup->high[TOP_LEVEL-j] = 255;
         }
         tup->low[TOP_LEVEL-i] = 0;
         tup->high[TOP_LEVEL-i] = cur->low[i]-1;
         if (tup->low[TOP_LEVEL-i]<=tup->high[TOP_LEVEL-i])
            ProcessDest(pr,tup,stack);
         tup->low[TOP_LEVEL-i] = cur->high[i]+1;
         tup->high[TOP_LEVEL-i] = 255;
         if (tup->low[TOP_LEVEL-i]<=tup->high[TOP_LEVEL-i])
            ProcessDest(pr,tup,stack);
         tup->low[TOP_LEVEL-i] = cur->low[i];
         tup->high[TOP_LEVEL-i] = cur->high[i];
      }
      return;
   }
   for (i=0;i<=cur->mask/8;i++){
      int j;
      for (j=i+1;j<4;j++){
         tup->low[TOP_LEVEL-j] = 0;
         tup->high[TOP_LEVEL-j] = 255;
      }
      tup->low[TOP_LEVEL-i] = 0;
      tup->high[TOP_LEVEL-i] = cur->low[i]-1;
      if (tup->low[TOP_LEVEL-i]<=tup->high[TOP_LEVEL-i])
         ProcessDest(pr,tup,stack);
      tup->low[TOP_LEVEL-i] = cur->high[i]+1;
      tup->high[TOP_LEVEL-i] = 255;
      if (tup->low[TOP_LEVEL-i]<=tup->high[TOP_LEVEL-i])
         ProcessDest(pr,tup,stack);
      tup->low[TOP_LEVEL-i] = cur->low[i];
      tup->high[TOP_LEVEL-i] = cur->high[i];
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
            tup->low[TOP_LEVEL-i] = cur->low[i];
            tup->high[TOP_LEVEL-i] = cur->high[i];
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

   if (head == NULL)            // If the list is empty, we're done.
      return;

   BuildRules(head->next, stack);       // In Reverse order.

#ifdef STACK_DEBUG
   printf("Processing Firewall: %d Chain: %d Rule: %d\n", head->fw_id, head->chain_id, head->id); 
#endif

   if (head->pktcond <=1){               // Temporarily, ignore PKTTYPE flags.
      rule_tuple *tup;                   // A placeholder output tuple
      tup = new rule_tuple;
      ProcessSource(head, tup, stack);     // Initiate the processing chain.
      delete tup;
   }

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
      // If we've gotten past the last rule, we just copy the inputMDD
      // and return.
      FWForest->Attach(outMDD, inMDD.index);
      HistoryForest->Attach(outHistMDD, inHistMDD.index);
      return;
   }

   rule_tuple *prev, *cur;
   
   cur = tup;
   prev = NULL;
   while (cur != NULL){
      rule_tuple* tmp;
      tmp = cur->next;
      cur->next = prev;
      prev = cur;
      cur = tmp;
   }

   //Process Each Rule
   cur = prev;
   while (cur != NULL){

      if (cur->high[0] == -1) {
         // If it's a log rule, insert it into the Log MDD and continue processing.
         cur->low[0] = cur->high[0] = 1;
         FWForest->Assign(logMDD, cur->low, cur->high, logMDD);
         cur->low[0] = cur->high[0] = -1;
         return;
      }

      // Create the intermediate MDDs
      for (int k=TOP_LEVEL;k>=0;k--){
         cur->hlow[k+3] = cur->low[k];
         cur->hhigh[k+3] = cur->high[k];
      } 

      cur->hlow[3] = cur->hhigh[3] = cur->fw_id;
      cur->hlow[2] = cur->hhigh[2] = cur->chain_id; 
      cur->hlow[1] = cur->hhigh[1] = cur->id;  

      cur->hlow[0] = cur->low[0];
      cur->hhigh[0] = cur->high[0];
   
      // If the rule is a terminating rule (ACCEPT, DROP, OR REJECT)
      // We simply insert it into the MDD.
      if (cur->low[0] < NUM_DEFAULT_TARGETS) {

#ifdef BUILD_DEBUG 
//      printf("B: Firewall %d, Chain %d, Rule %d: MDD %d\n", tup->fw_id, tup->chain_id, tup->id, inMDD.index);
//      for (int k=22;k>0;k--)
//	 FWForest->Compact(k);
//      FWForest->PrintMDD();
#endif

         FWForest->Assign(inMDD, cur->low, cur->high, inMDD);
         HistoryForest->Assign(inHistMDD, cur->hlow, cur->hhigh, inHistMDD);

#ifdef BUILD_DEBUG
      printf("A: Firewall %d, Chain %d, Rule %d: MDD %d\n", cur->fw_id, cur->chain_id, cur->id, inMDD.index);
      PrintRuleTuple(cur);
      for (int k=22;k>0;k--)
	 FWForest->Compact(k);
      FWForest->PrintMDD();
#endif


         // Since we are doing things in reverse order, it's possible
         // that a rule that logs packets is shadowed by the current
	 // rule.  So, we erase any shadowed packets from the log MDD
	 // right here.
	 
         int oldTarget = cur->low[0];
         cur->low[0] = cur->high[0] = 0;
         FWForest->Assign(logMDD, cur->low, cur->high, logMDD);

         // Restore the tuple in case it is reachable through another chain.
         cur->low[0] = cur->high[0] = oldTarget;  
      }
      else { //The target is another chain.

	 //Lookup the chain
         chain *nextChain = chain_array[cur->low[0] - NUM_DEFAULT_TARGETS];

         mdd_handle targetMDD;
         mdd_handle targetHistMDD;

	 //Build an MDD for the other chain.  Only terminal nodes in this MDD
	 //will be "ACCEPT", "DROP", "REJECT", and 0 ("Undefined").
         ProcessChain(chain_array, inMDD, inHistMDD, nextChain->tup, targetMDD,
   	       logMDD, targetHistMDD);

         mdd_handle resultMDD;
         mdd_handle resultHistMDD;
   
	 //Build an MDD representing the packets that match the current rule.
	 //Terminal of this rule will be the id of the target chain.
         FWForest->MakeMDDFromTuple(cur->low, cur->high, criteriaMDD);
         HistoryForest->MakeMDDFromTuple(cur->hlow, cur->hhigh, historyMDD);

	 //Take only nodes in the target MDD that match nodes in the criteria MDD by doing
	 //an intersection.  If the criteria node is "zero", return "zero".  Otherwise, 
	 //if the target node is "zero", we keep the criteria node (i.e. will map to the chain number).
         FWForest->ProjectOnto(targetMDD, criteriaMDD, resultMDD);
         HistoryForest->ProjectOnto(targetHistMDD, historyMDD, resultHistMDD);

         // Clean up criteriaMDDs.
         FWForest->DestroyMDD(criteriaMDD);
         HistoryForest->DestroyMDD(historyMDD);

         //Throw away the nodes that do not map to ACCEPT or DROP and intersect with inMDD to produce the result.
	 
	 FWForest->Replace(inMDD, resultMDD, true, inMDD);//outMDD?
         HistoryForest->Replace(inHistMDD, resultHistMDD, true, inHistMDD); //Is this correct?@@@@

         FWForest->DestroyMDD(resultMDD);
         HistoryForest->DestroyMDD(resultHistMDD);
         FWForest->DestroyMDD(targetMDD);
         HistoryForest->DestroyMDD(targetHistMDD);
      }
      cur = cur->next;
   }
   FWForest->Attach(outMDD, inMDD.index);
   HistoryForest->Attach(outHistMDD, inHistMDD.index);
}

// Initiate construction of outMDD and logMDD.
void Firewall::AssembleChains(chain ** chain_array, chain * chain,
                              mdd_handle & outMDD, mdd_handle & logMDD, mdd_handle & outHistMDD)
{
   // Here we set the default policy for the builtin chain.

   mdd_handle initMDD;
   mdd_handle initHistMDD;

   int low[TOP_LEVEL+1], hlow[TOP_LEVEL+1+3];
   int high[TOP_LEVEL+1], hhigh[TOP_LEVEL+1+3];

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

   for (int i=0;i<=TOP_LEVEL;i++){
      hhigh[i+3] = high[i];
      hlow[i+3] = low[i];
   }
//   hlow[0] = 1;
//   hhigh[0] = 1;
   hlow[0] = hhigh[0] = chain->Default;

   hlow[1] = 0;   //Rule ID.
   hhigh[1] = 0;  //Default Policy is rule 0.

   hlow[2] = chain->id; //Chain ID.
   hhigh[2] = chain->id;

   hlow[3] = id;  //Firewall ID
   hhigh[3] = id;

   // Create an MDD representing the default policy
   FWForest->MakeMDDFromTuple(low, high, initMDD);
   HistoryForest->MakeMDDFromTuple(hlow, hhigh, initHistMDD);

   // It becomes the initial "inMDD" to ProcessChain.
   if (chain->tup != NULL) {
      ProcessChain(chain_array, initMDD, initHistMDD, chain->tup, outMDD, logMDD, outHistMDD);
      FWForest->DestroyMDD(initMDD);
      HistoryForest->DestroyMDD(initHistMDD);
   }
   else {
      FWForest->Attach(outMDD, initMDD.index);
      HistoryForest->Attach(outHistMDD, initHistMDD.index);
   }
}
