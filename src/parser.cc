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

//#define ASSERT_DEBUG
//#define EXAMPLE_DEBUG

#include <stdlib.h>
#include <stdio.h>
#include "parser.h"
#include "fwlang.tab.hh"
#include "firewall.h"

extern FILE* yyin;

// Limit of 256 address groups
group *groups[256];
int num_groups = 0;

// Limit of 256 service groups
service *services[256];
int num_services = 0;

// A firewall object 
Firewall *FW;

// Link the Firewall Forest to the Query Engine.
void InitializeStructures(Firewall * F)
{
   FW = F;
}

// Given the name of a service, find it in the service array and return
// it.  
// If no such service is found, return NULL.

service *ServiceLookup(char *name)
{
   int i;

   for (i = 0; i < num_services; i++) {
      if (strncmp(name, services[i]->name, 256) == 0) {
         return services[i];
      }
   }
   printf("Service %s not found.\n", name);
   exit(-1);
   return NULL;
}

// Given the name of a group, find it in the group array and return it.
// If no such group is found, return NULL.
group *GroupLookup(char *name)
{
   int i;

   for (i = 0; i < num_groups; i++) {
      if (strncmp(name, groups[i]->name, 256) == 0) {
         return groups[i];
      }
   }
   printf("\nError: Could not find group <%s>.  Did you define it?\n", name);
   exit(-1);
   return NULL;
}

// Construct a new Service, consisting of the single port p;
service *BuildServiceFromPort(port * p)
{
   service *s;
   char tmp[256];

   s = new service;
   s->list = p;
   sprintf(tmp, "Service %d-%d", p->low, p->high);
   strncpy(s->name, tmp, 256);
   s->named = 0;
   return s;
}

// Construct a new Service, consisting of the single port p;
group *BuildGroupFromAddress(address * a)
{
   group *g;
   char tmp[256];
   int flag;

   g = new group;
   g->list = a;
   flag = 0;
   for (int i = 0; i < 4; i++) {
      if (a->high[i] != a->low[i]) {
         flag = 1;
         break;
      }
   }
   if (flag == 1) {
      sprintf(tmp, "Group %d-%d.%d-%d.%d-%d.%d-%d", a->low[0], a->high[0],
              a->low[1], a->high[1], a->low[2], a->high[2], a->low[3],
              a->high[3]);
   }
   else {
      sprintf(tmp, "Group %d.%d.%d.%d", a->high[0], a->high[1], a->high[2],
              a->high[3]);
   }
   strncpy(g->name, tmp, 256);
   g->named = 0;
   return g;
}

// Given a string containing the port number, return its value as an
// integer.
port *ParsePort(char *str)
{
   port *newPort;

   newPort = new port;
   if (!newPort) {
      printf("Failed to allocate memory for port %s\n", str);
      return NULL;
   }
   newPort->next = NULL;
   if (str[0] == '*') {
      newPort->low = -1;
      newPort->high = -1;
   }
   else if (sscanf(str, "%d", &newPort->low) == 0) {
      printf("\nInvalid port: %s\n", str);
      delete newPort;

      return NULL;
   }
   newPort->high = newPort->low;
   return newPort;
}

void ProcessComponent(char *piece, int length, int& low, int& high){
   if (piece == NULL || length < 1 || piece[0] == '*') {
      low = -1;
      high = -1;
   }
   else if (piece[0] == '['){
      char* first;
      char* second;
      int pos;
      int start;
      pos = 1;

      first = new char[length-1];
      for (int i=0;i<length-1;i++)
	 first[i] = '\0';
      while (pos<=length && piece[pos] != '-'){
         first[pos-1] = piece[pos];
         pos++;
      }
      sscanf(first, "%d", &low);
      delete[] first;
      if (piece[pos] != '-'){
         printf("Incorrectly formatted range: %s [F%d].\n", piece, pos);
         exit(-1);
      }

      pos++; // Advance past the - sign
      
      start = pos;
      second = new char[length-1];
      for (int i=0;i<length-1;i++)
	 second[i] = '\0';
      while (pos<=length && piece[pos] != ']'){
         second[pos-start] = piece[pos];
         pos++;
      }
      if (piece[pos] != ']'){
         printf("Incorrectly formatted range: %s [S%d].\n", piece, pos);
         exit(-1);
      }
      sscanf(second, "%d", &high);
      delete[] second;
   }
   else {
      sscanf(piece, "%d", &low);
      high = low;
   }
}

// Convert the string representation of an address into an address
// struct.
address *ParseAddr(char *val1, char *val2, char *val3, char *val4)
{
   address *newAddr;
   newAddr = new address;
   if (!newAddr) {
      printf("Failed to allocate memory for address %s.%s.%s.%s\n",
             val1 != NULL ? val1 : "*", val2 != NULL ? val2 : "*",
             val3 != NULL ? val3 : "*", val4 != NULL ? val4 : "*");
      return NULL;
   }
   ProcessComponent(val1,strlen(val1),newAddr->low[0], newAddr->high[0]);
   ProcessComponent(val2,strlen(val2),newAddr->low[1], newAddr->high[1]);
   ProcessComponent(val3,strlen(val3),newAddr->low[2], newAddr->high[2]);
   ProcessComponent(val4,strlen(val4),newAddr->low[3], newAddr->high[3]);
   newAddr->next = NULL;
   return newAddr;
}

// Create a "condition" object representing the set of all logged
// packets.
condition *GetLoggedCondition(int input_chain)
{
   condition *sc;

   sc = new condition;
   switch(input_chain){
      case 0:
         FW->FWForest->Attach(sc->h, FW->InputLog.index); 
#ifndef NO_HISTORY
         FW->HistoryForest->Attach(sc->history, FW->InputHist.index); 
#endif
	 break;
      case 1:
         FW->FWForest->Attach(sc->h, FW->ForwardLog.index);
#ifndef NO_HISTORY
         FW->HistoryForest->Attach(sc->history, FW->ForwardHist.index); 
#endif
	 break;
      case 2:
         FW->FWForest->Attach(sc->h, FW->OutputLog.index);  
#ifndef NO_HISTORY
         FW->HistoryForest->Attach(sc->history, FW->OutputHist.index); 
#endif
	 break;
      default:
	 printf("Illegal input chain to Logged.\n");
	 break;
   }
#ifdef ASSERT_DEBUG
   printf("Logged: %d\n", sc->h.index);
#endif
   return sc;
}

condition* BuildAcceptCondition(int input_chain)
{
   condition *sc;

   sc = new condition;
   switch(input_chain){
      case 0:
         FW->FWForest->Accepted(FW->Input, sc->h); 
#ifndef NO_HISTORY
         FW->HistoryForest->Accepted(FW->InputHist, sc->history); 
#endif
	 break;
      case 1:
         FW->FWForest->Accepted(FW->Forward, sc->h); 
#ifndef NO_HISTORY
         FW->HistoryForest->Accepted(FW->ForwardHist, sc->history); 
#endif
	 break;
      case 2:
         FW->FWForest->Accepted(FW->Output, sc->h); 
#ifndef NO_HISTORY
         FW->HistoryForest->Accepted(FW->OutputHist, sc->history); 
#endif
	 break;
      default:
	 printf("Illegal input chain to Logged.\n");
	 break;
   }
#ifdef ASSERT_DEBUG
   printf("Accept Condition: %d\n", sc->h.index);
   for (int k=22;k>0;k--)
      FW->FWForest->Compact(k);
   FW->FWForest->PrintMDD();
#endif
   return sc;
}

condition* BuildDropCondition(int input_chain)
{
   condition *sc;

   sc = new condition;
   switch(input_chain){
      case 0:
         FW->FWForest->Dropped(FW->Input, sc->h);
#ifndef NO_HISTORY
         FW->HistoryForest->Dropped(FW->InputHist, sc->history); 
#endif
	 break;
      case 1:
         FW->FWForest->Dropped(FW->Forward, sc->h); 
#ifndef NO_HISTORY
         FW->HistoryForest->Dropped(FW->ForwardHist, sc->history);
#endif
	 break;
      case 2:
         FW->FWForest->Dropped(FW->Output, sc->h); 
#ifndef NO_HISTORY
         FW->HistoryForest->Dropped(FW->OutputHist, sc->history); 
#endif
	 break;
      default:
	 printf("Illegal input chain to Logged.\n");
	 break;
   }
   /*
   for (int k=22;k>0;k--)
      FW->FWForest->Compact(k);
   printf("Dropped(%d):%d\n",input_chain, sc->h.index);
   FW->FWForest->PrintMDD();
   */
#ifdef ASSERT_DEBUG
   printf("DROPPED Condition: %d\n", sc->h.index);
   for (int k=22;k>0;k--)
      FW->FWForest->Compact(k);
   FW->FWForest->PrintMDD();
#endif
   return sc;
}

// Create a condition object representing the set of 
// ip addresses in group g.
// If op is 0, they are stored as source addresses.
// If op is 1, they are stored as destination addresses.
condition *BuildConditionFromGroup(group * g, int op)
{

   condition *sc;
   int *low;
   int *high;

#ifndef NO_HISTORY
   int *hlow;
   int *hhigh;
#endif

   address *prev;
   address *cur;
   int i;

   low = new int[23];
   high = new int[23];
   
#ifndef NO_HISTORY
   hlow = new int[25];
   hhigh = new int[25];
#endif

   sc = new condition;

   cur = g->list;
   while (cur != NULL) {
      // Initialize all elements of the tuple to [0-MAX]
      for (i = 22; i >= 1; i--) {
         low[i] = 0;
         high[i] = FW->FWForest->GetMaxVal(i);
#ifndef NO_HISTORY         
         hlow[i+2] = 0;
         hhigh[i+2] = FW->HistoryForest->GetMaxVal(i+2);
#endif
      }
      // If it's a source address group, copy the values into positions
      // 19 through 22.
      if (op == 0) {
         for (i = 22; i > 18; i--) {
            low[i] = cur->low[22 - i];
            high[i] = cur->high[22 - i];
#ifndef NO_HISTORY
            hlow[i+2] = cur->low[22 - i];
            hhigh[i+2] = cur->high[22 - i];
#endif
            if (cur->high[22 - i] < 0) {
               low[i] = 0;
               high[i] = FW->FWForest->GetMaxVal(i);
#ifndef NO_HISTORY
               hlow[i+2] = 0;
               hhigh[i+2] = FW->HistoryForest->GetMaxVal(i+2);
#endif
            }
         }
         // If it's a destination address group, copy them into
         // positions
         // 15 through 18.
      }
      else {
         for (i = 18; i > 14; i--) {
            low[i] = cur->low[18 - i];
            high[i] = cur->high[18 - i];
#ifndef NO_HISTORY
            hlow[i+2] = cur->low[18 - i];
            hhigh[i+2] = cur->high[18 - i];
#endif
            if (cur->high[18 - i] < 0) {
               low[i] = 0;
               high[i] = FW->FWForest->GetMaxVal(i);
#ifndef NO_HISTORY
               hlow[i+2] = 0;
               hhigh[i+2] = FW->HistoryForest->GetMaxVal(i+2);
#endif
            }
         }
      }
      // 1 means in the query, 0 means not in the query.
      high[0] = low[0] = 1;
#ifndef NO_HISTORY
      hlow[0] = hhigh[0] = 1;

      hlow[1] = hlow[2] = 0;
      hhigh[1] = hhigh[2] = FW->HistoryForest->GetMaxVal(2);
#endif
      // If this is the first address, we use MakeMDDFromTuple
      // Otherwise, we use Assign.
      if (sc->h.index == -1)
         FW->FWForest->MakeMDDFromTuple(low, high, sc->h);
      else
         FW->FWForest->Assign(sc->h, low, high, sc->h);
#ifndef NO_HISTORY
      FW->HistoryForest->Assign(sc->history, hlow, hhigh, sc->history);
#endif
   
      prev = cur;
      cur = cur->next;
      if (g->named == 0) {
         delete prev;
      }
   }
   delete[]high;
   delete[]low;
#ifndef NO_HISTORY
   delete[]hhigh;
   delete[]hlow;
#endif
   if (g->named == 0)
      delete g;
#ifdef ASSERT_DEBUG
   printf("\nGroup: %d\n", sc->h.index);
#endif
   return sc;
}

// Create a condition object representing the set of 
// TCP or UDP ports in service s.
// If op is 0, they are stored as source ports.
// If op is 1, they are stored as destination ports.
condition *BuildConditionFromService(service * s, int op)
{
   condition *sc;
   int *low;
   int *high;

#ifndef NO_HISTORY
   int *hlow;
   int *hhigh;
#endif

   port *cur;
   port *prev;
   int i;

   low = new int[23];
   high = new int[23];
#ifndef NO_HISTORY
   hlow = new int[25];
   hhigh = new int[25];
#endif

   sc = new condition;

   cur = s->list;
   while (cur != NULL) {
      // Initialize all values to [0-MAX]
      for (i = 22; i >= 1; i--) {
         low[i] = 0;
         high[i] = FW->FWForest->GetMaxVal(i);
#ifndef NO_HISTORY
         hlow[i+2] = 0;
         hhigh[i+2] = FW->HistoryForest->GetMaxVal(i+2);
#endif
      }
      // If it's a source port, break it into two bytes
      // and store it in positions 10 and 11.
      if (op == 0) {
         if (cur->low >= 0) {
            high[13] = cur->high / 256;
            low[13] = cur->low / 256;
            high[12] = cur->high % 256;
            low[12] = cur->low % 256;

#ifndef NO_HISTORY
            hhigh[15] = cur->high / 256;
            hlow[15] = cur->low / 256;
            hhigh[14] = cur->high % 256;
            hlow[14] = cur->low % 256;
#endif
         }
      }
      else {
         // If it's a destination port, break it into two bytes
         // and store it in positions 8 and 9.
         if (cur->low >= 0) {
            high[11] = cur->high / 256;
            low[11] = cur->low / 256;
            high[10] = cur->high % 256;
            low[10] = cur->low % 256;
            
#ifndef NO_HISTORY
            hhigh[13] = cur->high / 256;
            hlow[13] = cur->low / 256;
            hhigh[12] = cur->high % 256;
            hlow[12] = cur->low % 256;
#endif
         }
      }
      // If it's a "BOTH" query, use UDP(1) and TCP(2)
      if (cur->protocol < 0) {
         low[14] = 1;
         high[14] = 2;

#ifndef NO_HISTORY
         hlow[16] = 1;
         hhigh[16] = 2;
#endif
      }
      else {
         // Otherwise, just copy the protocol value into position 12.
         high[14] = low[14] = cur->protocol;
        
#ifndef NO_HISTORY
	 hhigh[16] = hlow[16] = cur->protocol;
#endif
      }

      // 1 means in the query, 0 means not in the query.
      high[0] = low[0] = 1;
#ifndef NO_HISTORY
      hlow[0] = hlow[1] = 0;

      hhigh[1] = hhigh[2] = FW->HistoryForest->GetMaxVal(2);
      hhigh[0] = hlow[0] = 1;
#endif
      // If this is the first port, use MakeMDDFromTuple.
      // Otherwise, use Assign.
      if (sc->h.index == -1)
         FW->FWForest->MakeMDDFromTuple(low, high, sc->h);
      else
         FW->FWForest->Assign(sc->h, low, high, sc->h);
#ifndef NO_HISTORY         
      for (int k=22;k>=0;k--){
	 hlow[k+2] = low[k];
	 hhigh[k+2] = high[k];
      }
      hlow[1] = hlow[2] = 0;
      hhigh[1] = hhigh[2] = FW->HistoryForest->GetMaxVal(2);
      hlow[0] = hhigh[0] = 1;
      FW->HistoryForest->Assign(sc->history, hlow, hhigh, sc->history);
#endif
      prev = cur;
      cur = cur->next;
      if (s->named == 0) {
         delete prev;
      }
   }
#ifdef DEBUG
   printf("%.256s\n", s->name);
   for (level k = 22; k > 0; k--) {
      printf("%d-%d ", low[k], high[k]);
      FW->FWForest->Compact(k);
   }
   printf("\n");
   FW->FWForest->PrintMDD();
#endif
   delete[]high;
   delete[]low;

#ifndef NO_HISTORY
   delete[]hhigh;
   delete[]hlow;
#endif

   if (s->named == 0)
      delete s;

#ifdef ASSERT_DEBUG
   printf("Service: %d\n", sc->h.index);
#endif
   return sc;
}

// Build a condition object representing all packets
// with state value equal to "state".
condition *BuildConditionFromState(int state)
{
   condition *sc;
   int *low;
   int *high;

#ifndef NO_HISTORY
   int *hlow;
   int *hhigh;
#endif

   int i;

   low = new int[23];
   high = new int[23];
#ifndef NO_HISTORY
   hlow = new int[25];
   hhigh = new int[25];
#endif

   sc = new condition;

   // Initialize all elements to [0-MAX]
   for (i = 22; i >= 1; i--) {
      low[i] = 0;
      high[i] = FW->FWForest->GetMaxVal(i);
#ifndef NO_HISTORY
      hlow[i+2] = 0;
      hhigh[i+2] = FW->HistoryForest->GetMaxVal(i+2);
#endif
   }
   // Set position 7 according to the value of state.  
   high[7] = low[7] = state;
#ifndef NO_HISTORY
   hhigh[9] = hlow[9] = state;
#endif
   // 1 means in the query, 0 means not in the query.
   high[0] = low[0] = 1;
#ifndef NO_HISTORY
   hhigh[0] = hlow[0] = 1;

   hlow[1] = hlow[2] = 0;
   hhigh[1] = hhigh[2] = FW->HistoryForest->GetMaxVal(2);
#endif
   // Make an MDD from the tuple.
   FW->FWForest->MakeMDDFromTuple(low, high, sc->h);
#ifndef NO_HISTORY
   FW->HistoryForest->MakeMDDFromTuple(hlow, hhigh, sc->history);
#endif
   delete[]high;
   delete[]low;
#ifndef NO_HISTORY
   delete[]hhigh;
   delete[]hlow;
#endif

#ifdef ASSERT_DEBUG
   printf("State: %d\n", sc->h.index);
#endif
   return sc;
}

//Build a condition representing the set of all packets on iface "name".
condition *BuildConditionFromIface(char *name, int in_out)
{
   condition *newCond;
   int *low;
   int *high;

#ifndef NO_HISTORY
   int *hlow;
   int *hhigh;
#endif

   int i;

   newCond = new condition;
   low = new int[23];
   high = new int[23];
#ifndef NO_HISTORY
   hlow = new int[25];
   hhigh = new int[25];
#endif
   // Initialize all elements to [0-MAX]
   for (i = 22; i >= 1; i--) {
      low[i] = 0;
      high[i] = FW->FWForest->GetMaxVal(i);
#ifndef NO_HISTORY
      hlow[i+2] = 0;
      hhigh[i+2] = FW->HistoryForest->GetMaxVal(i+2);
#endif
   }

   if (FW->T == NULL) {
      low[0] = high[0] = 1;
#ifndef NO_HISTORY
      hlow[0] = hlow[1] = 0;
      hhigh[1] = hhigh[2] = FW->HistoryForest->GetMaxVal(2);
      hhigh[0] = hlow[0] = 1;
#endif
      // Make an MDD from the tuple.
      FW->FWForest->MakeMDDFromTuple(low, high, newCond->h);
#ifndef NO_HISTORY
      FW->HistoryForest->MakeMDDFromTuple(hlow, hhigh, newCond->history);
#endif
      delete[]high;
      delete[]low;
#ifndef NO_HISTORY
      delete []hhigh;
      delete []hlow;
#endif
      return newCond;
   }

   switch (in_out) {
      case 0:
         low[9] = high[9] = FW->T->FindInterface(name);
#ifndef NO_HISTORY
         hlow[11] = hhigh[11] = FW->T->FindInterface(name);
#endif
         if (low[9] < 0)
            printf("Warning: Could not find input interface: %s\n", name);
         break;
      case 1:
         low[8] = high[8] = FW->T->FindInterface(name);
#ifndef NO_HISTORY
         hlow[10] = hhigh[10] = FW->T->FindInterface(name);
#endif
         if (low[8] < 0)
            printf("Warning: Could not find output interface: %s\n", name);
         break;
   }
   // 1 means in the query, 0 means not in the query.
   low[0] = high[0] = 1;
#ifndef NO_HISTORY
   hhigh[0] = hlow[0] = 1;

   hlow[1] = hlow[2] = 0;
   hhigh[1] = hhigh[2] = FW->HistoryForest->GetMaxVal(2);
#endif
   // Make an MDD from the tuple.
   FW->FWForest->MakeMDDFromTuple(low, high, newCond->h);
#ifndef NO_HISTORY
   FW->HistoryForest->MakeMDDFromTuple(hlow, hhigh, newCond->history);
#endif

#ifdef DEBUG
   for (level k = 22; k > 0; k--)
      FW->FWForest->Compact(k);
   FW->FWForest->PrintMDD();
#endif

   delete[]high;
   delete[]low;
#ifndef NO_HISTORY
   delete[]hhigh;
   delete[]hlow;
#endif
   return newCond;
}

// Build a condition representing the set of all packets with "flag" set.
condition *BuildConditionFromFlag(int flag)
{
   condition *newCond;
   int *low;
   int *high;

#ifndef NO_HISTORY
   int *hlow;
   int *hhigh;
#endif

   int i;

   newCond = new condition;
   low = new int[23];
   high = new int[23];
#ifndef NO_HISTORY
   hlow = new int[25];
   hhigh = new int[25];
#endif

   // Initialize all elements to [0-MAX]
   for (i = 22; i >= 1; i--) {
      low[i] = 0;
      high[i] = FW->FWForest->GetMaxVal(i);
#ifndef NO_HISTORY
      hlow[i+2] = 0;
      hhigh[i+2] = FW->HistoryForest->GetMaxVal(i+2);
#endif
   }

   // Set the appropriate value to 1.
   switch (flag) {
      case 0:                  // FIN
         low[6] = high[6] = 1;
#ifndef NO_HISTORY
         hlow[8] = hhigh[8] = 1;
#endif
         break;
      case 1:                  // SYN
         low[5] = high[5] = 1;
#ifndef NO_HISTORY
         hlow[7] = hhigh[7] = 1;
#endif
         break;
      case 2:                  // RST
         low[4] = high[4] = 1;
#ifndef NO_HISTORY
         hlow[6] = hhigh[6] = 1;
#endif
         break;
      case 3:                  // PSH
         low[3] = high[3] = 1;
#ifndef NO_HISTORY
         hlow[5] = hhigh[5] = 1;
#endif
         break;
      case 4:                  // ACK
         low[2] = high[2] = 1;
#ifndef NO_HISTORY
         hlow[4] = hhigh[4] = 1;
#endif
         break;
      case 5:                  // URG
         low[1] = high[1] = 1;
#ifndef NO_HISTORY
         hlow[3] = hhigh[3] = 1;
#endif
         break;
      default:
         printf("Bad TCP flag: %d.\n", flag);
         exit(-1);
   }
   // 1 means in the query, 0 means not in the query.
   low[0] = high[0] = 1;
#ifndef NO_HISTORY
   hlow[0] = hhigh[0] = 1;

   hlow[1] = hlow[2] = 0;   
   hhigh[1] = hhigh[2] = FW->HistoryForest->GetMaxVal(2);
#endif
   // Make an MDD from the tuple.
   FW->FWForest->MakeMDDFromTuple(low, high, newCond->h);
#ifndef NO_HISTORY
   FW->HistoryForest->MakeMDDFromTuple(hlow, hhigh, newCond->history);
#endif
   delete[]high;
   delete[]low;
#ifndef NO_HISTORY
   delete[]hhigh;
   delete[]hlow;
#endif
   return newCond;
}

// Given a condition c, create a new condition which represents the
// set complement of c.
condition *NegateCondition(condition * c)
{
   condition *newCond;

   newCond = new condition;

   // Use the binary complement operator, which stores the
   // result in newCond->h.
   FW->FWForest->BinaryComplement(c->h, newCond->h);
#ifndef NO_HISTORY
   FW->HistoryForest->BinaryComplement(c->history, newCond->history);
#endif

#ifdef ASSERT_DEBUG
   printf("OldCondition: %d\n", c->h.index);
#endif
   // We can now free the initial condition
   FW->FWForest->DestroyMDD(c->h);
   delete c;

#ifdef DEBUG
   printf("Negate\n");
   for (level k = 22; k > 0; k--)
      FW->FWForest->Compact(k);
   FW->FWForest->PrintMDD();
#endif
#ifdef ASSERT_DEBUG
   printf("Negate: %d\n", newCond->h.index);
#endif
   return newCond;
}

// Given two conditions c1 and c2, return the set union of c1 and c2.
condition *UnionConditions(condition * c1, condition * c2)
{
   condition *newCond;

   newCond = new condition;

   // We use the "MAX" operation on MDDs, which stores
   // the result in newCond->h.
   FW->FWForest->Max(c1->h, c2->h, newCond->h);
#ifndef NO_HISTORY
   FW->HistoryForest->Max(c1->history, c2->history, newCond->history);
#endif
   // Now c1 and c2 are no longer useful, so they can be freed.
   FW->FWForest->DestroyMDD(c1->h);
   FW->FWForest->DestroyMDD(c2->h);
#ifndef NO_HISTORY
   FW->HistoryForest->DestroyMDD(c1->history);
   FW->HistoryForest->DestroyMDD(c2->history);
#endif
   delete c1;
   delete c2;

#ifdef DEBUG
   printf("Union\n");
   for (level k = 22; k > 0; k--)
      FW->FWForest->Compact(k);
   FW->FWForest->PrintMDD();
#endif
#ifdef ASSERT_DEBUG
   printf("Union: %d\n", newCond->h.index);
#endif
   return newCond;
}

// Given two conditions c1 and c2, return the set intersection of c1 and
// c2.  
condition *IntersectConditions(condition * c1, condition * c2)
{
   condition *newCond;

   newCond = new condition;

   // Use the MIN operation on MDDs.
   FW->FWForest->Min(c1->h, c2->h, newCond->h);
#ifndef NO_HISTORY
   FW->HistoryForest->Min(c1->history, c2->history, newCond->history);
#endif
   // Now we can free c1 and c2.

   // If c1 or c2 is a "Group" condition, does this BREAK STUFF?

   FW->FWForest->DestroyMDD(c1->h);
   FW->FWForest->DestroyMDD(c2->h);
#ifndef NO_HISTORY
   FW->HistoryForest->DestroyMDD(c1->history);
   FW->HistoryForest->DestroyMDD(c2->history);
#endif
   delete c1;
   delete c2;

#ifdef DEBUG
   printf("Intersect\n");
#endif
#ifdef ASSERT_DEBUG
   printf("Intersect: %d\n", newCond->h.index);
#endif
   return newCond;
}

query *PerformQuery(int subject, condition * c)
{
   int mask[23];

   for (int i = 0; i < 23; i++)
      mask[i] = 0;
   

   // Intersect the set of accepted packets with the set of packets
   // relevant to the query (stored in condition "c").
#ifdef DEBUG
   printf("Rules: %d Query: %d\n", FW->Forward.index, c->h.index);
   //FW->FWForest->PruneMDD(c->h);
   for (level k = 22; k > 0; k--)
      FW->FWForest->Compact(k);
   FW->FWForest->PrintMDD();
#endif

   // "Project" the results to Display the requested information
   switch (subject) {
      case 0:
         FW->FWForest->PruneMDD(c->h);
         for (level k = 22; k > 0; k--)
            FW->FWForest->Compact(k);
         FW->FWForest->PrintMDD();
         // FW->FWForest->PrintStates(c->h.index);
         break;
      case 1:
         printf("# Ports: ");
         // Source port starts at level 13
         mask[14] = 1;
         mask[13] = 1;
         mask[12] = 1;
         FW->FWForest->PrintRanges(c->h, mask);
         break;
      case 2:
         printf("# Ports: ");
         // Destination port starts at level 11
         mask[14] = 1;
         mask[11] = 1;
         mask[10] = 1;
         FW->FWForest->PrintRanges(c->h, mask);
//         FW->FWForest->PrintPort(c->h, 8);
         break;
      case 3:
         printf("# Addresses: ");
         // Source addresses start at level 22
         mask[22] = 1;
         mask[21] = 1;
         mask[20] = 1;
         mask[19] = 1;
         FW->FWForest->PrintRanges(c->h, mask);
         //FW->FWForest->PrintAddy(c->h, 22);
         break;
      case 4:
         printf("# Addresses: ");
         // Destination addresses start at level 18
         mask[18] = 1;
         mask[17] = 1;
         mask[16] = 1;
         mask[15] = 1;
         FW->FWForest->PrintRanges(c->h, mask);
         break;
      case 5:
         printf("# States: ");
         // The state value is stored at level 7
         mask[7] = 1;
         FW->FWForest->PrintRanges(c->h, mask);
         break;
   }
   // Now that the query is done, free the query condition.
   FW->FWForest->DestroyMDD(c->h);
#ifndef NO_HISTORY
   FW->HistoryForest->DestroyMDD(c->history);
#endif
   delete c;
   return NULL;
}

assert* PerformAssertion(condition* left, condition* right, int assert_op, int example, int history){
   int cond;
   int* tup;
   condition* notA;
   condition* notB;
   condition* resultA;
   condition* resultB;
   condition* resultC;
   condition* resultD;

   resultA = new condition;
   resultB = new condition;
   resultC = new condition;
   resultD = new condition;
   notA = new condition;
   notB = new condition;

   mdd_handle mergedHistory;
   mdd_handle resultHistory;
  
   FW->HistoryForest->Max(FW->InputHist, FW->OutputHist, mergedHistory);
   FW->HistoryForest->Max(FW->ForwardHist, mergedHistory, mergedHistory);
  
   FW->FWForest->BinaryComplement(left->h, notA->h);
   FW->FWForest->BinaryComplement(right->h, notB->h);
   
   FW->HistoryForest->BinaryComplement(left->history, notA->history);
//   printf("Left: %d notA: %d\n", left->history.index, notA->history.index);
//   for (int k=25;k>0;k--)
//      FW->HistoryForest->Compact(k);
//   FW->HistoryForest->PrintMDD();
   
   FW->HistoryForest->BinaryComplement(right->history, notB->history);

   #ifdef EXAMPLE_DEBUG
   printf("ASSERT_OP: %d\n", assert_op);
   printf("NotA: %d\n", notA->h.index);
   printf("NotB: %d\n", notB->h.index);
   #endif

   FW->FWForest->Min(notA->h, right->h, resultA->h);
   FW->HistoryForest->Min(notA->history, right->history, resultA->history);
   FW->FWForest->Min(left->h, notB->h, resultB->h);
   FW->HistoryForest->Min(left->history, notB->history, resultB->history);

   FW->FWForest->Max(resultA->h, resultB->h, resultC->h);
   FW->HistoryForest->Max(resultA->history, resultB->history, resultC->history);

   FW->FWForest->Min(left->h, right->h, resultD->h);
   FW->FWForest->Min(left->history, right->history, resultD->history);

#ifdef EXAMPLE_DEBUG
	    printf("Left: %d Right:%d\n", left->h.index, right->h.index);
	    printf("ResultA: %d\n", resultA->h.index);
	    printf("ResultB: %d\n", resultB->h.index);
	    printf("ResultC: %d\n", resultC->h.index);
	    printf("ResultD: %d\n", resultD->h.index);
#endif
   
   switch (assert_op){
      case OP_IS:
         if (resultA->h.index != 0){
            printf("#Assertion failed.\n");
            FW->FWForest->FindElement(resultA->h, FW->T, tup);
            FW->HistoryForest->Min(mergedHistory, resultA->history, resultHistory);
            cond = false;
         }
         else if (resultB->h.index != 0){
            printf("#Assertion failed.\n");
            FW->FWForest->FindElement(resultB->h, FW->T, tup);
            FW->HistoryForest->Min(mergedHistory, resultB->history, resultHistory);
            cond = false;
         }
         else{
            printf("#Assertion held.\n");
            FW->FWForest->FindElement(left->h, FW->T, tup);
            FW->HistoryForest->Min(mergedHistory, left->history, resultHistory);
            cond = true;
         }
      break;
      case OP_SUBSET:
         if (resultB->h.index == 0){
	    printf("#Assertion held.\n");
            FW->FWForest->FindElement(left->h, FW->T, tup);
            FW->HistoryForest->Min(mergedHistory, left->history, resultHistory);
            cond = true;
	 }
	 else{
	    printf("#Assertion failed.\n");
            FW->FWForest->FindElement(resultB->h, FW->T, tup);
            FW->HistoryForest->Min(mergedHistory, resultB->history, resultHistory);
            cond = false;
        }
      break;
      case OP_NOT_IS:
      if (resultA->h.index != 0){
	  printf("#Assertion held.\n");
          FW->FWForest->FindElement(resultA->h,FW->T, tup);
          FW->HistoryForest->Min(mergedHistory, resultA->history, resultHistory);
          cond = true;
      }
      else if (resultB->h.index !=0){
	  printf("#Assertion held.\n");
          FW->FWForest->FindElement(resultB->h,FW->T, tup);
          FW->HistoryForest->Min(mergedHistory, resultB->history, resultHistory);
          cond = true;
      }
      else{
	  printf("#Assertion failed.\n");
          FW->FWForest->FindElement(left->h,FW->T, tup);
          FW->HistoryForest->Min(mergedHistory, left->history, resultHistory);
          cond = false;
      }
      break;
      case OP_NOT_SUBSET:
      if (resultB->h.index !=0){
         printf("#Assertion held.\n");
         FW->FWForest->FindElement(resultB->h, FW->T, tup);
         FW->HistoryForest->Min(mergedHistory, resultB->history, resultHistory);
         cond = true;
      }
      else{
         printf("#Assertion failed.\n");
         FW->FWForest->FindElement(left->h, FW->T, tup);
         FW->HistoryForest->Min(mergedHistory, left->history, resultHistory);
         cond = false;
      }
      break;
   }
   if (example){
      if (cond){
         printf("#Witness:\n");
      }
      else{
         printf("#Counterexample:\n");
      }
      if (tup != NULL){
         FW->FWForest->PrintElement(FW->T, tup);
#ifndef NO_HISTORY
         if (history){
            printf("Critical Rules:\n");
            FW->HistoryForest->DisplayHistory(resultHistory, tup);
//            printf("History MDD:%d\n", resultHistory.index);
//            for (int k=25;k>0;k--)
//               FW->HistoryForest->Compact(k);
//            FW->HistoryForest->PrintMDD();
         }
#endif
         delete[] tup;
      }
   }
   delete resultA;
   delete resultB;
   delete resultC;
   delete notA;
   delete notB;
   delete left;
   delete right;
}

// Add port "newPort" to the port list "list" and return the result.
port *AppendPort(port * list, port * newPort)
{
   newPort->next = list;
   return newPort;
}

// Add the address "newAddy" to the address list "list" and return the
// result.
address *AppendAddy(address * list, address * newAddy)
{
   newAddy->next = list;
   return newAddy;
}

// From a linked list of ports and a name string, create a 
// service struct and store it in the service array.
service *DefineService(char *name, port * list)
{
   service *s;

   s = new service;
   strncpy(s->name, name, 256);
   s->named = 1;
   s->list = list;
   services[num_services] = s;
   num_services++;
   return s;
}

// From a linked list of addresses and a name string, create a 
// group struct and store it in the group array.
group *DefineGroup(char *name, address * list)
{
   group *g;

   g = new group;
   strncpy(g->name, name, 256);
   g->named = 1;
   g->list = list;
   groups[num_groups] = g;
   num_groups++;
   return g;
}

// Set the protocol for port "p" to "protocol" and return the result.
port *BuildPort(int protocol, port * p)
{
   p->protocol = protocol;
   return p;
}

void DoCleanup()
{
   int i;
   address *nextAddy;
   port *nextPort;

   for (i = 0; i < num_groups; i++) {
      while (groups[i]->list != NULL) {
         nextAddy = groups[i]->list;
         groups[i]->list = groups[i]->list->next;
         delete nextAddy;
      }
      delete groups[i];

      groups[i] = NULL;
   }
   for (i = 0; i < num_services; i++) {
      while (services[i]->list != NULL) {
         nextPort = services[i]->list;
         services[i]->list = services[i]->list->next;
         delete nextPort;
      }
      delete services[i];

      services[i] = NULL;
   }
   FW->FWForest->DestroyMDD(FW->Input);
   FW->FWForest->DestroyMDD(FW->Output);
   FW->FWForest->DestroyMDD(FW->Forward);
#ifndef NO_HISTORY
   FW->HistoryForest->DestroyMDD(FW->InputHist);
   FW->HistoryForest->DestroyMDD(FW->OutputHist);
   FW->HistoryForest->DestroyMDD(FW->ForwardHist);
#endif
   FW->FWForest->DestroyMDD(FW->InputLog);
   FW->FWForest->DestroyMDD(FW->OutputLog);
   FW->FWForest->DestroyMDD(FW->ForwardLog);
}

query *PrintClasses()
{

   FW->PrintClasses();          //Nodes at level 19.
   return NULL;
}

query *PrintServiceClasses()
{

   FW->PrintServiceClasses();
   return NULL;
}

query *PrintServiceGraph()
{
   address* fromAd;
   address* toAd;
   group **grps;
   int numGroups;

   FW->GetClasses(grps, numGroups);
   for (int i=0;i<numGroups;i++){
      for (int j=0;j<numGroups;j++){
        service* arcs;
        int numArcs;

         fromAd = grps[i]->list;
         toAd = grps[j]->list;
         FW->GetServiceGraph(fromAd->low, toAd->low, arcs, numArcs);

         printf("There are %d arcs from %s to %s\n", numArcs, grps[i]->name, grps[j]->name);
//         printf("There are %d arcs from %d.%d.%d.%d to %d.%d.%d.%d\n", numArcs, fromAd->low[0], fromAd->low[1], fromAd->low[2], fromAd->low[3], toAd->low[0],toAd->low[1],toAd->low[2],toAd->low[3]);
         port* curPort;
         int lastVal;
         int lastProt;
         lastVal = -1;
         curPort = arcs->list;
         if (curPort != NULL){
            printf("%d Port %d-", curPort->protocol, curPort->low);
            lastVal = curPort->high;
            lastProt = curPort->protocol;
            curPort = curPort->next;
         }
         while (curPort != NULL){
            if (curPort->protocol != lastProt || curPort->low != lastVal - 1){
               printf("%d\n", curPort->protocol, curPort->high);
               printf("%d Port %d-", curPort->protocol, curPort->low);
            }
            lastVal = curPort->high;
            lastProt = curPort->protocol;
            curPort = curPort->next;
         }
         if (lastVal>=0)
            printf("%d\n", lastVal);
      }
   }
   return NULL;
}

void PrintAddyList(address * list)
{
   address *cur;

   cur = list;
   while (cur != NULL) {
      printf("%d-%d.%d-%d.%d-%d.%d-%d ", cur->low[0], cur->high[0],
             cur->low[1], cur->high[1], cur->low[2], cur->high[2],
             cur->low[3], cur->high[3]);
      cur = cur->next;
   }
   printf("\n");
}

int yyparse();

void ParseQueryFile(char *filename){
   FILE* in;
   in = fopen(filename, "r");
   yyin = in;
   yyparse();
   fclose(in);
}
