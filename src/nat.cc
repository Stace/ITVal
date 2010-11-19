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

#include <string.h>
#include "nat.h"
#include <stdlib.h>
#include <FDDL/mdd.h>
#include "firewall.h"


void BreakMASQPorts(char *str, nat_range * &NATRange, char prot, Firewall * FW){
   char *ch;
   char word3[1024];
   char word4[1024];
   int length;
   //printf("MASQUERADE AND REDIRECT ports have not been implemented yet.\n");
   NATRange = new nat_range;
   NATRange->next = NULL;
   NATRange->ports.port1 = 0;
   NATRange->ports.port2 = 65535;
   NATRange->ports.next = NULL;
   for (int i = 0; i < 23; i++) {
      NATRange->low[i] = 0;
      NATRange->high[i] = FW->FWForest->GetMaxVal(i);
   }
   if (prot == 'a') {
      NATRange->low[14] = 0;
      NATRange->high[14] = 2;
   }
   else if (prot == 'i') {
      NATRange->low[14] = NATRange->high[14] = 0;
   }
   else if (prot == 'u') {
      NATRange->low[14] = NATRange->high[14] = 1;
   }
   else if (prot == 't') {
      NATRange->low[14] = NATRange->high[14] = 2;
   }
   str += 11;  //Scan past "masq ports:" or "redir ports".
   length = strlen(str);
   ch = str;
   while (ch - str < length && *ch != '-') {
      word3[ch - str] = *ch;
      word4[ch - str] = *ch; // Assume no port range
      ch++;
   }
   word3[ch - str] = '\0';
   word4[ch - str] = '\0';
   if (*ch == '-') {         // If there IS a range, get it.
      length -= (ch - str);
      str = ch;
      while (ch - str < length && *ch != ':') {
         word4[ch - str] = *ch;
         ch++;
      }
      word4[ch - str] = '\0';
   }
   sscanf(word3, "%d", &NATRange->ports.port1);
   sscanf(word4, "%d", &NATRange->ports.port2);
}

void BreakNAT(char *str, nat_range * &NATRange, char prot, Firewall * FW, char* target)
{
   char *ch;
   char word1[1024];
   char word2[1024];
   char word3[1024];
   char word4[1024];
   int length;
   int offset;

   NATRange = new nat_range;
   NATRange->next = NULL;
   NATRange->ports.port1 = 0;
   NATRange->ports.port2 = 65535;
   NATRange->ports.next = NULL;
   for (int i = 0; i < 23; i++) {
      NATRange->low[i] = 0;
      NATRange->high[i] = FW->FWForest->GetMaxVal(i);
   }

   str += 3;                    // Advance past "to:"

   length = strlen(str);
   ch = str;

   while (ch - str < length && *ch != '-' && *ch != ':') {
      word1[ch - str] = *ch;
      word2[ch - str] = *ch;    // Assume no range
      // printf("%c ", *ch);
      ch++;
   }
   word1[ch - str] = '\0';
   word2[ch - str] = '\0';
   if (*ch == '-') {            // If there IS a range, get it.
      ch++;                     // Advance past '-'
      length -= (ch - str);
      str = ch;
      while (ch - str < length && *ch != ':') {
         word2[ch - str] = *ch;
         ch++;
      }
      word2[ch - str] = '\0';
   }
   // Break Addresses into octets
   address_range low, high;
   ConvertARange(word1, &low);
   ConvertARange(word2, &high);
   
   for (int i=0; i<4; i++){
      NATRange->addys.low[i] = low.low[i];
      NATRange->addys.high[i] = high.high[i];
   }

   offset = 0;
   if (!strncmp(target, "SNAT",4)){
      offset = 4;
   }
   NATRange->low[18+offset] = NATRange->addys.low[0];
   NATRange->low[17+offset] = NATRange->addys.low[1];
   NATRange->low[16+offset] = NATRange->addys.low[2];
   NATRange->low[15+offset] = NATRange->addys.low[3];

   NATRange->high[18+offset] = NATRange->addys.high[0];
   NATRange->high[17+offset] = NATRange->addys.high[1];
   NATRange->high[16+offset] = NATRange->addys.high[2];
   NATRange->high[15+offset] = NATRange->addys.high[3];

   if (prot == 'a') {
      NATRange->low[14] = 0;
      NATRange->high[14] = 2;
   }
   else if (prot == 'i') {
      NATRange->low[14] = NATRange->high[14] = 0;
   }
   else if (prot == 'u') {
      NATRange->low[14] = NATRange->high[14] = 1;
   }
   else if (prot == 't') {
      NATRange->low[14] = NATRange->high[14] = 2;
   }

   if (*ch == ':') {
      ch++;                     // Advance past ':'
      length -= (ch - str);
      str = ch;
      while (ch - str < length && *ch != '-') {
         word3[ch - str] = *ch;
         word4[ch - str] = *ch; // Assume no port range
         ch++;
      }
      word3[ch - str] = '\0';
      word4[ch - str] = '\0';
      if (*ch == '-') {         // If there IS a range, get it.
         length -= (ch - str);
         str = ch;
         while (ch - str < length && *ch != ':') {
            word4[ch - str] = *ch;
            ch++;
         }
         word4[ch - str] = '\0';
      }
      sscanf(word3, "%d", &NATRange->ports.port1);
      sscanf(word4, "%d", &NATRange->ports.port2);
   }
   else {
      // No explicit port, so map to all ports.
      NATRange->ports.port1 = 0;
      NATRange->ports.port2 = 65535;
   }
   if (!strncmp(target, "DNAT", 4)){
      NATRange->low[13] = NATRange->low[13] = 0;
      NATRange->high[13] = NATRange->high[13] = 255;

      NATRange->low[12] = NATRange->low[12] = 0;
      NATRange->high[12] = NATRange->high[12] = 255;

      NATRange->low[11] = (NATRange->ports.port1 / 256) % 256;
      NATRange->low[10] = NATRange->ports.port1 % 256;

      NATRange->high[11] = (NATRange->ports.port2 / 256) % 256;
      NATRange->high[10] = NATRange->ports.port2 % 256;
   }
   else{
      NATRange->low[11] = NATRange->low[11] = 0;
      NATRange->high[11] = NATRange->high[11] = 255;

      NATRange->low[10] = NATRange->low[10] = 0;
      NATRange->high[10] = NATRange->high[10] = 255;

      NATRange->low[13] = (NATRange->ports.port1 / 256) % 256;
      NATRange->low[13] = NATRange->ports.port1 % 256;

      NATRange->high[12] = (NATRange->ports.port2 / 256) % 256;
      NATRange->high[12] = NATRange->ports.port2 % 256;
   }
}

void BreakNMAP(char *str, nat_range * &NATRange, Firewall * FW)
{
   char *ch;
   char word1[1024];
   int length;

   NATRange = new nat_range;
   NATRange->next = NULL;
   for (int i = 0; i < 23; i++) {
      NATRange->low[i] = 0;
      NATRange->high[i] = FW->FWForest->GetMaxVal(i);
   }

   length = strlen(str);
   ch = str;

   while (ch - str < length) {
      word1[ch - str] = *ch;
      ch++;
   }
   word1[ch - str] = '\0';
   ConvertARange(word1, &NATRange->addys);

   for (int i = 0; i < 4 ; i++){
      NATRange->low[i] = NATRange->addys.low[i];
      NATRange->high[i] = NATRange->addys.high[i];
   }
}

processed_nat_rule* ConvertToDNAT(processed_nat_rule * p, Firewall * FW){
   int* ip;
   processed_nat_rule *newP;
   newP = (processed_nat_rule *)p->next;
   if (p->out == -1){
      for (int outFace = 0; outFace<FW->T->numIfaces;outFace++){
         processed_nat_rule *newP2;
         newP2 = new processed_nat_rule;
	 newP2->from = new address_range;
	 newP2->to = new address_range;
	 newP2->sports = NULL;
	 newP2->dports = NULL;

         port_range* cur;
	 cur = p->sports;
	 while (cur != NULL){
	    port_range* newPort;
	    newPort = new port_range;
	    newPort->port1 = cur->port1;
	    newPort->port2 = cur->port2;
	    newPort->next = newP2->sports;
	    newP2->sports = cur;
	    cur = cur->next;
	 }
	 cur = p->dports;
	 while (cur != NULL){
	    port_range* newPort;
	    newPort = new port_range;
	    newPort->port1 = cur->port1;
	    newPort->port2 = cur->port2;
	    newPort->next = newP2->dports;
	    newP2->dports = cur;
	    cur = cur->next;
	 }
	 newP2->in = p->in;
	 newP2->out = outFace;
	 newP2->id = p->id;
	 newP2->chain_id = p->chain_id;
         nat_range* newRange;
	 newRange = new nat_range;
	 newRange->next = NULL;

	 //Should test that p->nat->ports.next is always NULL....
	 newRange->ports.port1 = p->nat->ports.port1;
	 newRange->ports.port2 = p->nat->ports.port2;
	 newRange->ports.next = NULL;
	 for (int i=0;i<23;i++){
            newRange->low[i] = 0;
	    newRange->high[i] = FW->FWForest->GetMaxVal(i);
	 }
	 char* name;
	 name = FW->T->LookupInterface(outFace);
	 if (!name){
	    printf("Error!  Could not find name for interface %d\n", outFace);
            return NULL;
	 }
         ip = FW->T->GetIP(name);
	 newRange->low[18] = ip[0];
	 newRange->low[17] = ip[1];
	 newRange->low[16] = ip[2];
	 newRange->low[15] = ip[3];
	 newRange->high[18] = ip[0];
	 newRange->high[17] = ip[1];
	 newRange->high[16] = ip[2];
	 newRange->high[15] = ip[3];
	 
	 delete[] ip;
         if (p->protocol == 'a') {
            newRange->low[14] = 0;
	    newRange->high[14] = 2;
	 }
         else if (p->protocol == 'i') {
	    newRange->low[14] = newRange->high[14] = 0;
	 }
         else if (p->protocol == 'u') {
	    newRange->low[14] = newRange->high[14] = 1;
	 }
	 else if (p->protocol == 't') {
	    newRange->low[14] = newRange->high[14] = 2;
         }
	 newRange->low[11] = (newRange->ports.port1 / 256) % 256;
	 newRange->low[10] = newRange->ports.port1 % 256;
	 newRange->high[11] = (newRange->ports.port2 / 256) % 256;
         newRange->high[10] = newRange->ports.port2 % 256;
	 newP2->nat = newRange;
	 newP2->next = newP;
	 newP = newP2;
      }
   }
   else{
         processed_nat_rule *newP2;
         newP2 = new processed_nat_rule;
	 newP2->from = new address_range;
	 newP2->to = new address_range;
	 newP2->sports = NULL;
	 newP2->dports = NULL;

         port_range* cur;
	 cur = p->sports;
	 while (cur != NULL){
	    port_range* newPort;
	    newPort = new port_range;
	    newPort->port1 = cur->port1;
	    newPort->port2 = cur->port2;
	    newPort->next = newP2->sports;
	    newP2->sports = cur;
	    cur = cur->next;
	 }
	 cur = p->dports;
	 while (cur != NULL){
	    port_range* newPort;
	    newPort = new port_range;
	    newPort->port1 = cur->port1;
	    newPort->port2 = cur->port2;
	    newPort->next = newP2->dports;
	    newP2->dports = cur;
	    cur = cur->next;
	 }
	 newP2->in = p->in;
	 newP2->out = p->out;
	 newP2->id = p->id;
	 newP2->chain_id = p->chain_id;
         nat_range* newRange;
	 newRange = new nat_range;
	 newRange->next = NULL;

	 //Should test that p->nat->ports.next is always NULL....
	 newRange->ports.port1 = p->nat->ports.port1;
	 newRange->ports.port2 = p->nat->ports.port2;
	 newRange->ports.next = NULL;
	 for (int i=0;i<23;i++){
            newRange->low[i] = 0;
	    newRange->high[i] = FW->FWForest->GetMaxVal(i);
	 }
	 char* name;
	 name = FW->T->LookupInterface(p->out);
	 if (!name){
	    printf("Error!  Could not find name for interface %d\n", p->out);
            return NULL;
	 }
         ip = FW->T->GetIP(name);
	 newRange->low[18] = ip[0];
	 newRange->low[17] = ip[1];
	 newRange->low[16] = ip[2];
	 newRange->low[15] = ip[3];
	 newRange->high[18] = ip[0];
	 newRange->high[17] = ip[1];
	 newRange->high[16] = ip[2];
	 newRange->high[15] = ip[3];
	 
	 delete[] ip;
         if (p->protocol == 'a') {
            newRange->low[14] = 0;
	    newRange->high[14] = 2;
	 }
         else if (p->protocol == 'i') {
	    newRange->low[14] = newRange->high[14] = 0;
	 }
         else if (p->protocol == 'u') {
	    newRange->low[14] = newRange->high[14] = 1;
	 }
	 else if (p->protocol == 't') {
	    newRange->low[14] = newRange->high[14] = 2;
         }
	 newRange->low[11] = (newRange->ports.port1 / 256) % 256;
	 newRange->low[10] = newRange->ports.port1 % 256;
	 newRange->high[11] = (newRange->ports.port2 / 256) % 256;
         newRange->high[10] = newRange->ports.port2 % 256;
	 newP2->nat = newRange;
	 newP2->next = newP;
	 newP = newP2;
   }
   return newP;
}

processed_nat_rule* ConvertToSNAT(processed_nat_rule * p, Firewall * FW){
   int* ip;
   processed_nat_rule *newP;
   newP = (processed_nat_rule *)p->next;
   if (p->in == -1){
      for (int inFace = 0; inFace <FW->T->numIfaces;inFace++){
         processed_nat_rule *newP2;
         newP2 = new processed_nat_rule;
	 newP2->from = new address_range;
	 newP2->to = new address_range;
	 newP2->sports = NULL;
	 newP2->dports = NULL;

         port_range* cur;
	 cur = p->sports;
	 while (cur != NULL){
	    port_range* newPort;
	    newPort = new port_range;
	    newPort->port1 = cur->port1;
	    newPort->port2 = cur->port2;
	    newPort->next = newP2->sports;
	    newP2->sports = cur;
	    cur = cur->next;
	 }
	 cur = p->dports;
	 while (cur != NULL){
	    port_range* newPort;
	    newPort = new port_range;
	    newPort->port1 = cur->port1;
	    newPort->port2 = cur->port2;
	    newPort->next = newP2->dports;
	    newP2->dports = cur;
	    cur = cur->next;
	 }
	 newP2->in = inFace;
	 newP2->out = p->out;
	 newP2->id = p->id;
	 newP2->chain_id = p->chain_id;
         nat_range* newRange;
	 newRange = new nat_range;
	 newRange->next = NULL;

	 //Should test that p->nat->ports.next is always NULL....
	 newRange->ports.port1 = p->nat->ports.port1;
	 newRange->ports.port2 = p->nat->ports.port2;
	 newRange->ports.next = NULL;
	 for (int i=0;i<23;i++){
            newRange->low[i] = 0;
	    newRange->high[i] = FW->FWForest->GetMaxVal(i);
	 }
	 char* name;
	 name = FW->T->LookupInterface(inFace);
	 if (!name){
	    printf("Error!  Could not find name for interface %d\n", inFace);
            return NULL;
	 }
         ip = FW->T->GetIP(name);
	 newRange->low[22] = ip[0];
	 newRange->low[21] = ip[1];
	 newRange->low[20] = ip[2];
	 newRange->low[19] = ip[3];
	 newRange->high[22] = ip[0];
	 newRange->high[21] = ip[1];
	 newRange->high[20] = ip[2];
	 newRange->high[19] = ip[3];
	 
	 delete[] ip;
         if (p->protocol == 'a') {
            newRange->low[14] = 0;
	    newRange->high[14] = 2;
	 }
         else if (p->protocol == 'i') {
	    newRange->low[14] = newRange->high[14] = 0;
	 }
         else if (p->protocol == 'u') {
	    newRange->low[14] = newRange->high[14] = 1;
	 }
	 else if (p->protocol == 't') {
	    newRange->low[14] = newRange->high[14] = 2;
         }
	 newRange->low[13] = (newRange->ports.port1 / 256) % 256;
	 newRange->low[12] = newRange->ports.port1 % 256;
	 newRange->high[13] = (newRange->ports.port2 / 256) % 256;
         newRange->high[12] = newRange->ports.port2 % 256;
	 newP2->nat = newRange;
	 newP2->next = newP;
	 newP = newP2;
      }
   }
   else{
         processed_nat_rule *newP2;
         newP2 = new processed_nat_rule;
	 newP2->from = new address_range;
	 newP2->to = new address_range;
	 newP2->sports = NULL;
	 newP2->dports = NULL;

         port_range* cur;
	 cur = p->sports;
	 while (cur != NULL){
	    port_range* newPort;
	    newPort = new port_range;
	    newPort->port1 = cur->port1;
	    newPort->port2 = cur->port2;
	    newPort->next = newP2->sports;
	    newP2->sports = cur;
	    cur = cur->next;
	 }
	 cur = p->dports;
	 while (cur != NULL){
	    port_range* newPort;
	    newPort = new port_range;
	    newPort->port1 = cur->port1;
	    newPort->port2 = cur->port2;
	    newPort->next = newP2->dports;
	    newP2->dports = cur;
	    cur = cur->next;
	 }
	 newP2->in = p->in;
	 newP2->out = p->out;
	 newP2->id = p->id;
	 newP2->chain_id = p->chain_id;
         nat_range* newRange;
	 newRange = new nat_range;
	 newRange->next = NULL;

	 //Should test that p->nat->ports.next is always NULL....
	 newRange->ports.port1 = p->nat->ports.port1;
	 newRange->ports.port2 = p->nat->ports.port2;
	 newRange->ports.next = NULL;
	 for (int i=0;i<23;i++){
            newRange->low[i] = 0;
	    newRange->high[i] = FW->FWForest->GetMaxVal(i);
	 }
	 char* name;
	 name = FW->T->LookupInterface(p->in);
	 if (!name){
	    printf("Error!  Could not find name for interface %d\n", p->in);
            return NULL;
	 }
         ip = FW->T->GetIP(name);
	 newRange->low[22] = ip[0];
	 newRange->low[21] = ip[1];
	 newRange->low[20] = ip[2];
	 newRange->low[19] = ip[3];
	 newRange->high[22] = ip[0];
	 newRange->high[21] = ip[1];
	 newRange->high[20] = ip[2];
	 newRange->high[19] = ip[3];
	 
	 delete[] ip;
         if (p->protocol == 'a') {
            newRange->low[14] = 0;
	    newRange->high[14] = 2;
	 }
         else if (p->protocol == 'i') {
	    newRange->low[14] = newRange->high[14] = 0;
	 }
         else if (p->protocol == 'u') {
	    newRange->low[14] = newRange->high[14] = 1;
	 }
	 else if (p->protocol == 't') {
	    newRange->low[14] = newRange->high[14] = 2;
         }
	 newRange->low[13] = (newRange->ports.port1 / 256) % 256;
	 newRange->low[12] = newRange->ports.port1 % 256;
	 newRange->high[13] = (newRange->ports.port2 / 256) % 256;
         newRange->high[12] = newRange->ports.port2 % 256;
	 newP2->nat = newRange;
	 newP2->next = newP;
	 newP = newP2;
   }
   return newP;
}

void ProcessNATInfo(char *info, processed_nat_rule * p, Firewall * FW,
                    rule_parser * rp)
{
   char port[1024];                       // String representation of the port
   char which[1024];                      // Which protocol the port is for

   // (tcp, udp, or icmp)
   int port_val;                          // Integer representation of the port 

   port_range *newPort;                   // Temporary range to be added to the rule 

   // 
   port_range *sports;                    // List of ranges for the source ports
   port_range *dports;                    // List of ranges for the destination

   // ports

   int state;                             // States to match

   nat_range *NATRange;                   // NATted Address

   char word1[1024];                      // Key name
   char word2[1024];                      // Value 

   int flags[6];                          // Which TCP flags to match

   int length;                            // Length of the info string

   int i;

   // Initially, the port lists are empty, all states match, and the
   // no flags are considered.
   sports = NULL;
   dports = NULL;
   NATRange = NULL;

   state = 0;
   for (i = 0; i < 6; i++)
      flags[i] = (-1);

   length = strlen(info);
   while (length - 1 > 0) {
      // Consume whitespace
      while (strlen(info) - 1 > 0 && (*info == ' ' || *info == '\t')) {
         info++;
      }
      // Read the first word (the key)
      if (sscanf(info, "%1024s", word1) != EOF) {
         info += strlen(word1);
         // If it's tcp or udp, scan in a port.
         if (!strncmp(word1, "tcp", 1024) || !strncmp(word1, "udp", 1024)) {
            // Read the port number into word2
            if (sscanf(info, "%1024s", word2) != EOF) {
               info += strlen(word2);
               // Convert the string into an integer
               rp->BreakPort(word2, which, port);
               // If it's a destination port, put it in the dports
               // list.  If it's a source port, put it in the sports
               // list.
               if (!strncmp(which, "dpt", 1024)) {
                  newPort = new port_range;
                  newPort->next = dports;
                  port_val = atoi(port);
                  newPort->port1 = port_val / 256;
                  newPort->port2 = port_val % 256;
                  dports = newPort;
               }
               else if (!strncmp(which, "spt", 1024)) {
                  newPort = new port_range;
                  newPort->next = sports;
                  port_val = atoi(port);
                  newPort->port1 = port_val / 256;
                  newPort->port2 = port_val % 256;
                  sports = newPort;
               }
            }
            // If the keyword is "state", then parse the state
            // information.
         }
         else if (!strncmp(word1, "state", 1024)) {
            if (sscanf(info, "%1024s", word2) != EOF) {
               info += strlen(word2);
               rp->BreakState(word2, &state);
            }
            // If it's "flags", parse the flag information.
         }
         else if (!strncmp(word1, "flags:", 6)) {
            rp->BreakFlags(word1, flags);
         }
         else if (!strncmp(word1, "to:", 3)) {  // SNAT or DNAT
            BreakNAT(word1, NATRange, p->protocol, FW, p->target);
            p->nat = NATRange;
         }
	 else if (!strncmp(word1, "masq ports:", 11)){ //MASQUERADE
            BreakMASQPorts(word1, NATRange, p->protocol, FW);
            p->nat = NATRange;
	 }
	 else if (!strncmp(word1, "redir ports", 11)){ //REDIRECT
            BreakMASQPorts(word1, NATRange, p->protocol, FW);
            p->nat = NATRange;
	 }
         else if (!strncmp(p->target, "NETMAP", 6)) {
            BreakNMAP(word1, NATRange, FW);
            p->nat = NATRange;
         }
      }
      length = strlen(info);
   }
   // Store the results in the processed_rule
   p->sports = sports;
   p->dports = dports;
   p->state = state;
   for (i = 0; i < 6; i++) {
      p->flags[i] = flags[i];
   }
   if (!strncmp(p->target, "MASQUERADE", 10)){
      processed_nat_rule * newP;
      newP = ConvertToSNAT(p,FW);
      delete p;
      p = newP;
   }
   if (!strncmp(p->target, "REDIRECT",8)){
      processed_nat_rule * newP;
      newP = ConvertToDNAT(p,FW);
      delete p;
      p = newP;
   }
}

// Convert an unprocessed rule r into a processed_rule p.
void ProcessNATRule(rule * r, processed_nat_rule * p, Firewall * FW,
                    rule_parser * rp)
{
   // Munge the source and destination addresses
   ConvertARange(r->source, p->from);
   ConvertARange(r->dest, p->to);

   // The protocol
   p->protocol = r->protocol[0];
   // The target
   strncpy(p->target, r->target, 256);

   p->nat = NULL;
   // And everything else
   ProcessNATInfo(r->info, p, FW, rp);
}
