/*
FDDL: A Free Decision Diagram Library
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


#include <stdio.h>
#include <assert.h>
#include "fwmdd.h"
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX(a, b) (a>b ? a : b)
#define MIN(a, b) (a<b ? a : b)

//#define HISTORY_DEBUG

int fw_fddl_forest::PrintElement(Topology* T, int* vals){
   char flagString[7]="FSRPAU";
      if (vals[14]==0)
	 printf("#ICMP");
      else if (vals[14]==1)
	 printf("#UDP");
      else 
	 printf("#TCP");
      printf(" packet from %d.%d.%d.%d:%d[%s] to %d.%d.%d.%d:%d[%s]\n#\t\t in state ",
	    vals[22], vals[21],vals[20], vals[19], 
	    vals[13]*256+vals[12],
	    T->LookupInterface(vals[9]),
	    vals[18], vals[17], vals[16], vals[15], 
	    vals[11]*256+vals[10],
	    T->LookupInterface(vals[8]));

      if (vals[7] == 0)
	 printf("INVALID");
      else if (vals[7] == 1)
	 printf("NEW");
      else if (vals[7] == 2)
	 printf("ESTABLISHED");
      else if (vals[7] == 3)
	 printf("RELATED");

      printf(" with flags[");
      for (int i=0;i<6;i++){
         if (vals[i+1] == 1){
            printf("%c", flagString[i]);
	 }
	 else printf(" ");
      }
      printf("].\n");
}

int fw_fddl_forest::FindElement(mdd_handle root, Topology* T, int*& vals){
   node_idx newresult;
   if (root.index < 0)
      return INVALID_MDD;

   vals = new int[K+1];
   for (int k=0;k<K+1;k++)
      vals[k]=0;

   if (InternalFindElement(K, root.index, vals) != 0){
      return SUCCESS;
   }
   delete[] vals;
   vals = NULL;
   return INVALID_MDD;
}

node_idx fw_fddl_forest::InternalFindElement(level k, node_idx p, int* vals){
   node* nodeP;
   node_idx q;
   if (k==0){
      vals[k] = p;
      return p != 0;
   }
   nodeP = &FDDL_NODE(k,p);
   for (int i=0;i<nodeP->size;i++){
      q = FDDL_ARC(k,nodeP,i);
      if (InternalFindElement(k-1, q, vals) != 0){
	 vals[k] = i;
         return p;
      }
   }
   return 0;
}

int fw_fddl_forest::DisplayHistory(mdd_handle root, int* vals){
   node_idx newresult;
   if (root.index < 0)
      return INVALID_MDD;

   if (InternalDisplayHistory(K, root.index, vals, 0) != 0){
      return SUCCESS;
   }
   return INVALID_MDD;
}

node_idx fw_fddl_forest::InternalDisplayHistory(level k, node_idx p,
int* vals, int chain){
   node* nodeP;
   node_idx q;
   
#ifdef HISTORY_DEBUG
   if (k>=2)
      printf("DH: <%d,%d>[%d],%d,%d\n", k,p,vals[k-2],chain);
   else
      printf("DH: <%d,%d>[-],%d,%d\n", k,p,chain);
#endif
   if (p==0){
      return 0;
   }
   if (k==0){
      return p;
   }
   nodeP = &FDDL_NODE(k,p);
   if (k==1){
      int found;
      found = 0;
      for (int i=0;i<nodeP->size;i++){
         q = FDDL_ARC(k,nodeP,i);
         if (q != 0 && (InternalDisplayHistory(k-1, q, vals, 0) != 0)){
            printf("Chain %d Rule %d\n", chain, i);
            found = 1;
         }
      }
      return found;
   }
   if (k==2){
      for (int i=0;i<nodeP->size;i++){
         q = FDDL_ARC(k,nodeP,i);
         if (q !=0)
            InternalDisplayHistory(k-1, q, vals, i);
      }
      return 1;
   }
   q = FDDL_ARC(k, nodeP, vals[k-2]);
   if (q != 0){
      return InternalDisplayHistory(k-1,q,vals,0);
   }
   return 0;
}


int fw_fddl_forest::Accepted(mdd_handle root, mdd_handle& result){
   node_idx newresult;
   if (root.index < 0)
      return INVALID_MDD;

   for (level k=K;k>0;k--){
      FWCache[k]->Clear();
   }
   newresult = InternalAccepted(K, root.index);
   //PrintMDD();
   //printf("Accepted:: %d\n", newresult);
   if (result.index != newresult){
      ReallocHandle(result);
      Attach(result, newresult);
   }
   return SUCCESS;
}

int fw_fddl_forest::Dropped(mdd_handle root, mdd_handle& result){
   node_idx newresult;
   if (root.index < 0)
      return INVALID_MDD;

   for (level k=K;k>0;k--){
      FWCache[k]->Clear();
   }
   newresult = InternalDropped(K, root.index);
   if (result.index != newresult){
      ReallocHandle(result);
      Attach(result, newresult);
   }
   return SUCCESS;
}

node_idx fw_fddl_forest::InternalAccepted(level k, node_idx p){
   node_idx r;
   node* nodeP;
   if (p==0)
      return 0;
      
   if (k==0)
      return (p == 3) ? p : 0;

   r = FWCache[k]->Hit(k,p);
   if (r>=0)
      return r;

   r = NewNode(k);
   nodeP = &FDDL_NODE(k,p);
   for (int i=0;i<nodeP->size;i++){
      node_idx j;
      j = FDDL_ARC(k,nodeP, i);
      SetArc(k,r,i, InternalAccepted(k-1, j));
   }
   r = CheckIn(k,r);
   FWCache[k]->Add(k,p,r);
   return r;
}

node_idx fw_fddl_forest::InternalDropped(level k, node_idx p){
   node_idx r;
   node* nodeP;

   if (k==0){
      if (p==0) 
         return 1;
      return ((p == 2) || (p==1)) ? p : 0;
   }
   
   r = FWCache[k]->Hit(k,p);
   if (r>=0)
      return r;
   
   if (p==0){
      r = NewNode(k);
      node_idx j;
      j = InternalDropped(k-1,0);
      for (int i=0;i<=maxVals[k];i++){
         SetArc(k,r,i,j);
      }
      r = CheckIn(k,r);
      FWCache[k]->Add(k,p,r);
      return r;
   }
      
   r = NewNode(k);
   nodeP = &FDDL_NODE(k,p);
   for (int i=0;i<=maxVals[k];i++){
      node_idx j;
      if (i<nodeP->size)
         j = FDDL_ARC(k,nodeP, i);
      else
         j = 0;
      SetArc(k,r,i, InternalDropped(k-1, j));
   }
   r = CheckIn(k,r);
   FWCache[k]->Add(k,p,r);
   return r;
}

int fw_fddl_forest::QueryIntersect(mdd_handle root, mdd_handle root2, mdd_handle & result) {
   if (root.index < 0)
      return INVALID_MDD;
   if (root2.index < 0)
      return INVALID_MDD;
   node_idx newresult;

   for (level k = K; k > 0; k--) {
      FWCache[k]->Clear();
   }
#ifdef DEBUG
   PrintMDD();
   printf("\nQueryIntersect: %d %d\n", root.index, root2.index);
#endif
   newresult = InternalQIntersect(K, root.index, root2.index);
#ifdef DEBUG
   PrintMDD();
   printf("\nQueryIntersect (result): %d\n", root.index, newresult);
#endif 

   if (result.index != newresult) {
      ReallocHandle(result);
      Attach(result, newresult);
   }
   return SUCCESS;
}

int fw_fddl_forest::PrintHistory(mdd_handle root){
   if (root.index < 0)
      return INVALID_MDD;
   FWCache[0] = new cache;
   for (level k = K; k >= 0; k--) {
      FWCache[k]->Clear();
   }
   InternalPrintHistory(K, root.index, 0,0);
   delete FWCache[0];
   FWCache[0]=NULL;
   return SUCCESS;
}

void fw_fddl_forest::InternalPrintHistory(level k, node_idx p, int chain_num, int rule_num){
   int i;
   node* nodeP;
   int result;
   
   if (p==0)
      return;
   
   if (k==0){
      result = FWCache[0]->Hit(chain_num, rule_num);
      if (result >=0)
	 return;
      printf("Chain %d Rule %d\n", chain_num, rule_num);
      FWCache[0]->Add(chain_num, rule_num, 1);
      return;
   }

   result = FWCache[k]->Hit(p, 1);
   if (result >= 0)
      return;
   
   nodeP = &FDDL_NODE(k,p);
   if (k==1){
      for (int i=0;i<nodeP->size;i++){
         InternalPrintHistory(k-1, FDDL_ARC(k,nodeP,i), chain_num, i);
      }
   }
   else if (k==2){
      for (int i=0;i<nodeP->size;i++){
         InternalPrintHistory(k-1, FDDL_ARC(k,nodeP,i), i, 0);
      }
   }
   else{
      for (int i=0;i<nodeP->size;i++){
         InternalPrintHistory(k-1, FDDL_ARC(k,nodeP, i), 0, 0);
      }
   }
   FWCache[k]->Add(p, 1, 1);
}

int fw_fddl_forest::HistoryIntersect(mdd_handle root, mdd_handle root2, mdd_handle & result) {
   if (root.index < 0)
      return INVALID_MDD;
   if (root2.index < 0)
      return INVALID_MDD;
   node_idx newresult;

   for (level k = K; k > 0; k--) {
      FWCache[k]->Clear();
   }
   newresult = InternalHIntersect(K, root.index, root2.index);
   if (result.index != newresult) {
      ReallocHandle(result);
      Attach(result, newresult);
   }
   return 0;
}

int fw_fddl_forest::JoinClasses(mdd_handle root, mdd_handle root2,
                                mdd_handle & result, int &OutNumClasses)
{
   int numClasses;
   OutNumClasses = 0;

   if (root.index < 0)
      return INVALID_MDD;

   if (root2.index < 0)
      return INVALID_MDD;

   node_idx newresult;

   for (level k = K; k >= 0; k--) {
      FWCache[k]->Clear();
   }

   numClasses = 1;              // Class0 is automatic.
   newresult = InternalJoinClasses(K, root.index, root2.index, numClasses);
   if (result.index != newresult) {
      ReallocHandle(result);
      Attach(result, newresult);
   }
   OutNumClasses = numClasses;
   return SUCCESS;
}

int fw_fddl_forest::SNAT(mdd_handle root, nat_tuple * pnr,
                         mdd_handle & result)
{
   if (root.index < 0)
      return INVALID_MDD;
   if (pnr == NULL)
      return 0;
   node_idx newresult;

   for (level k = K; k > 0; k--) {
      FWCache[k]->Clear();
   }
   newresult = InternalSNAT(K, root.index, root.index, pnr);
   if (result.index != newresult) {
      ReallocHandle(result);
      Attach(result, newresult);
   }
   return 0;
}

int fw_fddl_forest::DNAT(mdd_handle root, nat_tuple * pnr,
                         mdd_handle & result)
{
   if (root.index < 0)
      return INVALID_MDD;
   if (pnr == NULL)
      return 0;
   node_idx newresult;

   for (level k = K; k > 0; k--) {
      FWCache[k]->Clear();
   }
   newresult = InternalDNAT(K, root.index, root.index, pnr);
   if (result.index != newresult) {
      ReallocHandle(result);
      Attach(result, newresult);
   }
   return 0;
}

int fw_fddl_forest::NETMAP(mdd_handle root, nat_tuple * pnr,
                           mdd_handle & result)
{
   if (root.index < 0)
      return INVALID_MDD;
   if (pnr == NULL)
      return 0;
   node_idx newresult;

   for (level k = K; k > 0; k--) {
      FWCache[k]->Clear();
   }
   newresult = InternalNMAP(K, root.index, root.index, pnr);
   if (result.index != newresult) {
      ReallocHandle(result);
      Attach(result, newresult);
   }
   return 0;
}

node_idx fw_fddl_forest::InternalSNAT(level k, node_idx p, node_idx q,
                                      nat_tuple * pnr)
{
   //Node p is the original address.
   //Node q is the NATTed address.
   arc_idx i;
   node_idx result, u;
   node *nodeP;
   node *nodeQ;
   node *nodeR;
   int psize;
   int qsize;

   if (k < 12) {                //If we're beyond the source port
      //return the node pointed to by the NATted address.
      result = CheckIn(k, q);
      return result;
   }

   //If cached, return the cached result.
   result = FWCache[k]->Hit(p, q);
   if (result >= 0)
      return result;

   result = NewNode(k);

   nodeR = &FDDL_NODE(k, result);

   if (k >= 19 || k < 14) {     //If it's a source address node
      if (p != 0) {             //And it's not zero.
         nodeP = &FDDL_NODE(k, p);
         for (int i = 0; i < pnr->low[k]; i++) {        //For arcs before the range, copy P.
            node_idx pchild;

            if (i < nodeP->size)
               pchild = FDDL_ARC(k, nodeP, i);
            else
               pchild = 0;
            SetArc(k, result, i, pchild);
         }

         for (int i = pnr->high[k] + 1; i <= maxVals[k]; i++) { //For arcs after the range, copy P.
            node_idx pchild;

            if (i < nodeP->size)
               pchild = FDDL_ARC(k, nodeP, i);
            else
               pchild = 0;
            SetArc(k, result, i, pchild);
         }
      }

      for (int i = pnr->low[k]; i <= pnr->high[k]; i++) {       //Addresses in the range, NAT.
         nat_range *cur;

         cur = pnr->nat;
         node_idx pchild;
         node_idx qchild;

         if (p == 0)
            pchild = 0;
         else {
            nodeP = &FDDL_NODE(k, p);
            if (i < nodeP->size)
               pchild = FDDL_ARC(k, nodeP, i);
            else
               pchild = 0;
         }

         node_idx rchild;

         if (i < nodeR->size)
            rchild = FDDL_ARC(k, nodeR, i);
         else
            rchild = 0;

         while (cur != NULL) {  //Need a while loop, because NAT rules can load balance.
            nodeQ = &FDDL_NODE(k, q);
            for (int j = cur->low[k]; j <= cur->high[k]; j++) {
               if (j < nodeQ->size)
                  qchild = FDDL_ARC(k, nodeQ, j);
               else
                  qchild = 0;
               u = InternalMax(k - 1, rchild,
                               InternalSNAT(k - 1, pchild, qchild, pnr));
               SetArc(k, result, i, u);
            }
            cur = cur->next;
         }
      }
   }
   else {                       //Otherwise, just recurse.
      node_idx pchild;
      node_idx qchild;

      nodeP = &FDDL_NODE(k, p);
      nodeQ = &FDDL_NODE(k, q);
      for (arc_idx i = 0; i <= maxVals[k]; i++) {
         if (i < nodeP->size)
            pchild = FDDL_ARC(k, nodeP, i);
         else
            pchild = 0;
         if (i < nodeQ->size)
            qchild = FDDL_ARC(k, nodeQ, i);
         else
            qchild = 0;
         u = InternalSNAT(k - 1, pchild, qchild, pnr);
         SetArc(k, result, i, u);
      }
   }
   result = CheckIn(k, result);
   FWCache[k]->Add(p, q, result);
   return result;
}

node_idx fw_fddl_forest::InternalDNAT(level k, node_idx p, node_idx q,
                                      nat_tuple * pnr)
{
   //Node p is the original address.
   //Node q is the NATTed address.
   arc_idx i;
   node_idx result, u;
   node *nodeP;
   node *nodeQ;
   node *nodeR;
   int psize;
   int qsize;

   if (k < 10) {                //If we're beyond the destination and port
      //return the node pointed to by the NATted address.
      result = CheckIn(k, q);
      return result;
   }

   //If cached, return the cached result.
   result = FWCache[k]->Hit(p, q);
   if (result >= 0)
      return result;

   result = NewNode(k);

   nodeR = &FDDL_NODE(k, result);

   if (k > 18) {
      assert(p == q);

      if (q == 0)               //If no address to NAT to, return 0.
         return 0;

      nodeQ = &FDDL_NODE(k, q);
      qsize = nodeQ->size;

      for (int i = 0; i <= maxVals[k]; i++) {
         node_idx child;
         node_idx rnode;

         if (i < nodeQ->size)
            child = FDDL_ARC(k, nodeQ, i);
         else
            child = 0;
         rnode = InternalDNAT(k - 1, child, child, pnr);
         SetArc(k, result, i, rnode);
      }
   }
   else {
      if (p != 0) {
         nodeP = &FDDL_NODE(k, p);
         for (int i = 0; i < pnr->low[k]; i++) {
            node_idx pchild;

            if (i < nodeP->size)
               pchild = FDDL_ARC(k, nodeP, i);
            else
               pchild = 0;
            SetArc(k, result, i, pchild);
         }
         for (int i = pnr->high[k] + 1; i <= maxVals[k]; i++) {
            node_idx pchild;

            if (i < nodeP->size)
               pchild = FDDL_ARC(k, nodeP, i);
            else
               pchild = 0;
            SetArc(k, result, i, pchild);
         }
      }
      for (int i = pnr->low[k]; i <= pnr->high[k]; i++) {
         nat_range *cur;

         cur = pnr->nat;
         node_idx pchild;
         node_idx qchild;

         if (p == 0)
            pchild = 0;
         else {
            nodeP = &FDDL_NODE(k, p);
            if (i < nodeP->size)
               pchild = FDDL_ARC(k, nodeP, i);
            else
               pchild = 0;
         }

         node_idx rchild;

         if (i < nodeR->size)
            rchild = FDDL_ARC(k, nodeR, i);
         else
            rchild = 0;

         while (cur != NULL) {
            nodeQ = &FDDL_NODE(k, q);
            for (int j = cur->low[k]; j <= cur->high[k]; j++) {
               if (j < nodeQ->size)
                  qchild = FDDL_ARC(k, nodeQ, j);
               else
                  qchild = 0;
               u = InternalMax(k - 1, rchild,
                               InternalDNAT(k - 1, pchild, qchild, pnr));
               SetArc(k, result, i, u);
            }
            cur = cur->next;
         }
      }
   }
   result = CheckIn(k, result);
   FWCache[k]->Add(p, q, result);
   return result;
}

node_idx fw_fddl_forest::InternalNMAP(level k, node_idx p, node_idx q,
                                      nat_tuple * pnr)
{                               //MODIFY!
   //Node p is the original address.
   //Node q is the NATTed address.

   arc_idx i;
   node_idx result, u;
   node *nodeP;
   node *nodeQ;
   node *nodeR;
   int psize;
   int qsize;

   if (k < 10) {
      //If we're beyond the destination and port
      //return the node pointed to by the NATted address.
      result = CheckIn(k, q);
      return result;
   }

   //If cached, return the cached result.
   result = FWCache[k]->Hit(p, q);
   if (result >= 0)
      return result;

   result = NewNode(k);

   nodeR = &FDDL_NODE(k, result);

   if (k > 18) {
      assert(p == q);

      if (q == 0)               //If no address to NAT to, return 0.
         return 0;

      nodeQ = &FDDL_NODE(k, q);
      qsize = nodeQ->size;

      for (int i = 0; i <= maxVals[k]; i++) {
         node_idx child;
         node_idx rnode;

         if (i < nodeQ->size)
            child = FDDL_ARC(k, nodeQ, i);
         else
            child = 0;
         rnode = InternalNMAP(k - 1, child, child, pnr);
         SetArc(k, result, i, rnode);
      }
   }
   else {
      if (p != 0) {
         nodeP = &FDDL_NODE(k, p);
         for (int i = 0; i < pnr->low[k]; i++) {
            node_idx pchild;

            if (i < nodeP->size)
               pchild = FDDL_ARC(k, nodeP, i);
            else
               pchild = 0;
            SetArc(k, result, i, pchild);
         }
         for (int i = pnr->high[k] + 1; i <= maxVals[k]; i++) {
            node_idx pchild;

            if (i < nodeP->size)
               pchild = FDDL_ARC(k, nodeP, i);
            else
               pchild = 0;
            SetArc(k, result, i, pchild);
         }
      }
      for (int i = pnr->low[k]; i <= pnr->high[k]; i++) {
         nat_range *cur;

         cur = pnr->nat;
         node_idx pchild;
         node_idx qchild;

         if (p == 0)
            pchild = 0;
         else {
            nodeP = &FDDL_NODE(k, p);
            if (i < nodeP->size)
               pchild = FDDL_ARC(k, nodeP, i);
            else
               pchild = 0;
         }

         node_idx rchild;

         if (i < nodeR->size)
            rchild = FDDL_ARC(k, nodeR, i);
         else
            rchild = 0;

         while (cur != NULL) {
            nodeQ = &FDDL_NODE(k, q);
            for (int j = cur->low[k]; j <= cur->high[k]; j++) {
               if (j < nodeQ->size)
                  qchild = FDDL_ARC(k, nodeQ, j);
               else
                  qchild = 0;
               u = InternalMax(k - 1, rchild,
                               InternalNMAP(k - 1, pchild, qchild, pnr));
               SetArc(k, result, i, u);
            }
            cur = cur->next;
         }
      }
   }
   result = CheckIn(k, result);
   FWCache[k]->Add(p, q, result);
   return result;
}

node_idx fw_fddl_forest::InternalQIntersect(level k, node_idx p, node_idx q)
{
   arc_idx i;
   node_idx result, u;
   node *nodeP, *nodeQ;
   int psize, qsize;
   int dummy;
   arc_idx *ptemp;
   arc_idx *qtemp;

   if (p == 0)
      return 0;                 //If it's not accepted

   if (q == 0)
      return 0;                 //Or not relevant to the query

   if (k == 0) {
      if (q == 2)
         return 1;              //If it's a log rule return 1.

      if (p == 3 && q == 1) {   //If it's relevant and accepted.
         return 1;
      }

      return 0;	
   }
   result = FWCache[k]->Hit(p, q);
   if (result >= 0)
      return result;

   result = NewNode(k);
   nodeP = &FDDL_NODE(k, p);
   nodeQ = &FDDL_NODE(k, q);

   if (IS_SPARSE(nodeP)) {      //If node <k.p> is stored sparsely, unpack it into a static array of appropriate size
      psize = UnpackNode(k, p, ptemp);
   }
   else {
      psize = nodeP->size;
      ptemp = new node_idx[psize];

      for (i = 0; i < psize; i++)
         ptemp[i] = FULL_ARC(k, nodeP, i);
   }
   if (IS_SPARSE(nodeQ)) {      //If node <k.q> is stored sparsely, unpack it into a static array of appropriate size
      qsize = UnpackNode(k, q, qtemp);
   }
   else {
      qsize = nodeQ->size;
      qtemp = new node_idx[qsize];

      for (i = 0; i < qsize; i++)
         qtemp[i] = FULL_ARC(k, nodeQ, i);
   }
   for (i = 0; i <= maxVals[k]; i++) {
      u = InternalQIntersect(k - 1, i < psize ? ptemp[i] : 0,
                             i < qsize ? qtemp[i] : 0);
      SetArc(k, result, i, u);
   }
   delete[]qtemp;
   delete[]ptemp;
   result = CheckIn(k, result);
   FWCache[k]->Add(p, q, result);
   return result;
}

node_idx fw_fddl_forest::InternalHIntersect(level k, node_idx p, node_idx q)
{
   arc_idx i;
   node_idx result, u;
   node *nodeP, *nodeQ;
   int psize, qsize;
   int dummy;
   arc_idx *ptemp;
   arc_idx *qtemp;

   if (p == 0)
      return 0;                 //If it's not accepted

   if (q == 0)
      return 0;                 //Or not relevant to the query

   if (k == 0) {
      if (p == 1 && q == 1) {   //If it's relevant and accepted.
         return 1;
      }
      return 0;
   }
   result = FWCache[k]->Hit(p, q);
   if (result >= 0)
      return result;

   result = NewNode(k);
   nodeP = &FDDL_NODE(k, p);
   nodeQ = &FDDL_NODE(k, q);

   if (IS_SPARSE(nodeP)) {      //If node <k.p> is stored sparsely, unpack it into a static array of appropriate size
      psize = UnpackNode(k, p, ptemp);
   }
   else {
      psize = nodeP->size;
      ptemp = new node_idx[psize];

      for (i = 0; i < psize; i++)
         ptemp[i] = FULL_ARC(k, nodeP, i);
   }
   if (IS_SPARSE(nodeQ)) {      //If node <k.q> is stored sparsely, unpack it into a static array of appropriate size
      qsize = UnpackNode(k, q, qtemp);
   }
   else {
      qsize = nodeQ->size;
      qtemp = new node_idx[qsize];

      for (i = 0; i < qsize; i++)
         qtemp[i] = FULL_ARC(k, nodeQ, i);
   }
   for (i = 0; i <= maxVals[k]; i++) {
      u = InternalHIntersect(k - 1, i < psize ? ptemp[i] : 0,
                             i < qsize ? qtemp[i] : 0);
      SetArc(k, result, i, u);
   }
   delete[]qtemp;
   delete[]ptemp;
   result = CheckIn(k, result);
   FWCache[k]->Add(p, q, result);
   return result;
}

int fw_fddl_forest::BuildClassMDD(mdd_handle p, fddl_forest * forest,
                                  mdd_handle & r, int &numClasses,
                                  int services)
{

   int *low;
   int *high;

   node_idx newresult;

   if (p.index < 0)
      return INVALID_MDD;

   if (forest == NULL)
      return INVALID_MDD;

   for (level k = K; k > 0; k--) {
      FWCache[k]->Clear();
   }

   numClasses = 1;
   newresult = InternalBuildClassMDD(forest, K, p.index, numClasses, services);
   if (r.index != newresult) {
      forest->ReallocHandle(r);
      forest->Attach(r, newresult);
   }
   return SUCCESS;
}

node_idx fw_fddl_forest::InternalBuildClassMDD(fddl_forest * forest, level k,
                                               node_idx p, int &numClasses,
                                               int services)
{
   node_idx r;
   level newK;

   newK = k - (18+services);
   
   r = FWCache[k]->Hit(k, p);
   if (r >= 0)
      return r;

   if (newK == 0) {
      FWCache[k]->Add(k, p, numClasses);
      numClasses++;
      return numClasses - 1;
   }

   r = forest->NewNode(newK);

   node *nodeP;
   if (p !=0)
      nodeP = &FDDL_NODE(k, p);
   else nodeP = NULL;
   
   for (arc_idx i = 0; i <= maxVals[k]; i++) {
      node_idx j;
      if (nodeP && i<nodeP->size)
         j = FDDL_ARC(k, nodeP, i);
      else
         j = 0;
      node_idx q;
      q = InternalBuildClassMDD(forest, k-1, j, numClasses, services);
      forest->SetArc(newK, r, i, q);
   }
   if ((*forest->nodes[newK])[r]->size == 0){ // If the node is empty.
      forest->DeleteNode(newK, r);
      r = 0;
   }
   else{
      r = forest->CheckIn(newK, r);
   }
   FWCache[k]->Add(k, p, r);
   return r;
}

int fw_fddl_forest::BuildServiceGraphMDD(mdd_handle p, fddl_forest * forest,
                                  mdd_handle & r, int &numArcs)
{

   int *low;
   int *high;

   node_idx newresult;

   if (p.index < 0)
      return INVALID_MDD;

   if (forest == NULL)
      return INVALID_MDD;

   for (level k = K; k >= 0; k--) {
      FWCache[k]->Clear();
   }

   numArcs = 0;
   newresult =
      InternalBuildServiceGraphMDD(forest, K, p.index, numArcs);
   if (r.index != newresult) {
      forest->ReallocHandle(r);
      forest->Attach(r, newresult);
   }
   return SUCCESS;
}

node_idx fw_fddl_forest::InternalBuildServiceGraphMDD(fddl_forest * forest, level k,
                                               node_idx p, int &numArcs)
{
   node_idx r;
   level newK;

   newK = k - 11;

   r = FWCache[k]->Hit(k, p);
   if (r >= 0)
      return r;

   if (p == 0) {
      FWCache[k]->Add(k, p, numArcs); //Is this a good idea?  I don't know.
      numArcs++;
      return numArcs - 1;
   }

   if (newK == 0) {
      FWCache[k]->Add(k, p, numArcs);
      numArcs++;
      return numArcs - 1;
   }

   r = forest->NewNode(newK);
   node *nodeP;
   nodeP = &FDDL_NODE(k, p);
   for (arc_idx i = 0; i < nodeP->size; i++) {
      forest->SetArc(newK, r, i,
                     InternalBuildServiceGraphMDD(forest, k - 1,
                                           FDDL_ARC(k, nodeP, i), numArcs));
   }
   r = forest->CheckIn(newK, r);
   FWCache[k]->Add(k, p, r);
   return r;
}

node_idx fw_fddl_forest::InternalJoinClasses(level k, node_idx p, node_idx q,
                                             int &numClasses)
{
   node_idx r;
   node *nodeP;
   node *nodeQ;

   if (p == 0 && q == 0)
      return 0;

   r = FWCache[k]->Hit(p, q);
   if (r >= 0)
      return r;

   if (k == 0) {
      numClasses++;
      FWCache[k]->Add(p, q, numClasses - 1);
      return numClasses - 1;
   }

   r = NewNode(k);

   if (p == 0) {
      nodeQ = &FDDL_NODE(k, q);
      for (arc_idx i = 0; i < nodeQ->size; i++) {
         SetArc(k, r, i,
                InternalJoinClasses(k - 1, 0, FDDL_ARC(k, nodeQ, i),
                                    numClasses));
      }
      r = CheckIn(k, r);
      FWCache[k]->Add(p, q, r);
      return r;
   }

   if (q == 0) {
      nodeP = &FDDL_NODE(k, p);
      for (arc_idx i = 0; i < nodeP->size; i++) {
         SetArc(k, r, i,
                InternalJoinClasses(k - 1, FDDL_ARC(k, nodeP, i), 0,
                                    numClasses));
      }
      r = CheckIn(k, r);
      FWCache[k]->Add(p, q, r);
      return r;
   }
   nodeP = &FDDL_NODE(k, p);
   nodeQ = &FDDL_NODE(k, q);
   for (arc_idx i = 0; i <= maxVals[k]; i++) {
      SetArc(k, r, i,
             InternalJoinClasses(k - 1,
                                 i < nodeP->size ? FDDL_ARC(k, nodeP, i) : 0,
                                 i < nodeQ->size ? FDDL_ARC(k, nodeQ, i) : 0,
                                 numClasses));
   }
   r = CheckIn(k, r);
   FWCache[k]->Add(p, q, r);
   return r;
}

int fw_fddl_forest::PrintClasses(mdd_handle p, int numClasses)
{
   int *low;
   int *high;
   if (p.index < 0)
      return INVALID_MDD;
   low = new int[5];
   high = new int[5];
   for (int i = 1; i < numClasses; i++) {
      printf("Class%d: \n", i);
      InternalPrintClasses(K, p.index, low, high, i);
   }
   delete[]low;
   delete[]high;
   return SUCCESS;
}

int fw_fddl_forest::PrintServiceClasses(mdd_handle p, int numClasses)
{
   int *low;
   int *high;
   if (p.index < 0)
      return INVALID_MDD;
   low = new int[4];
   high = new int[4];
   for (int i = 1; i < numClasses; i++) {
      printf("Class%d: \n", i);
      InternalPrintServiceClasses(K, p.index, low, high, i);
   }
   delete[]low;
   delete[]high;
   return SUCCESS;
}


void fw_fddl_forest::InternalPrintClasses(level k, node_idx p, int *low,
                                          int *high, int classNum)
{
   struct hostent *h;
   if (p == 0 || k == 0) {
      if (p == classNum) {
         printf("\t");
         int i;
         if (k==0){
            for (i=0;i<4;i++){
               if (k >=4-i)
                  break;
               if (low[4-i] != high[4-i])
                  break;
            }
            if (i==4){
               char addy[16];
               struct in_addr *addr;
               sprintf(addy, "%d.%d.%d.%d\0", low[4], low[3],low[2],low[1]);
               addr = new in_addr;
               if (inet_aton(addy,addr) != 0){
                  h = gethostbyaddr(addr, sizeof(addr), AF_INET);
                  if (h != NULL){
                     printf("%s(%s)\n", h->h_name, addy);
                     return;
                  }
               }
               delete addr;
            }
         }
         for (i=0;i<4;i++){
            if (k >= 4-i){
               printf("*");
            }
            else if (low[4-i] == high[4-i]){
               printf("%d", low[4-i]);
            }
            else{
               printf("[%d-%d]",  low[4-i], high[4-i]);
            }
            if (i < 3){
               printf(".");
            }
         }
         printf("\n");
      }
      return;
   }

   int lastVal;

   node *nodeP;
   nodeP = &FDDL_NODE(k, p);
   if (nodeP->size <1) 
      return;
   low[k] = 0;
   high[k] = 0;
   lastVal = FDDL_ARC(k, nodeP, 0);

   for (int i = 0; i < nodeP->size; i++) {
      if (lastVal == FDDL_ARC(k, nodeP, i)) {
         high[k] = i;
      }
      else {
         InternalPrintClasses(k - 1, lastVal, low, high, classNum);
         low[k] = i;
         high[k] = i;
         lastVal = FDDL_ARC(k, nodeP, i);
      }
   }
   InternalPrintClasses(k - 1, FDDL_ARC(k, nodeP, nodeP->size - 1), low, high,
                        classNum);
}

void fw_fddl_forest::InternalPrintServiceClasses(level k, node_idx p,
                                                 int *low, int *high,
                                                 int classNum)
{
   int pLow, pHigh;
   if (p == 0 || k == 0) {
      if (p == classNum) {
         printf("\t");
         if (k <= 3) {
            if (low[3] == high[3]) {
               switch (low[3]) {
                  case -1:
                     printf("BOTH: ");
                     break;
                  case 0:
                     printf("ICMP: ");
                     break;
                  case 1:
                     printf("UDP: ");
                     break;
                  case 2:
                     printf("TCP: ");
                     break;
                  default:
                     printf("Unknown Protocol[%d]: ", low[3]);
               }
            }
            else {
               if (low[3] == 0 && high[3] == 2)
                  printf("ALL: ");
               else if (low[3] == 1 && high[3] == 2)
                  printf("BOTH: ");
               else if (low[3] == 0 && high[3] == 1)
                  printf("ICMP + UDP: ");
               else
                  printf("Unknown[%d-%d]: ", low[3], high[3]);
            }
         }
         else {
            printf("ALL: ");
         }
         pLow = 0;
         pHigh = 255;
         if (k < 2) {
            pLow = low[2] * 255;
            pHigh = high[2] * 255;
         }
         if (k < 1) {
            pLow += low[1];
            pHigh += high[1];
         }
         printf("%d-%d\n", pLow, pHigh);
      }
      return;
   }

   int lastVal;

   node *nodeP;
   nodeP = &FDDL_NODE(k, p);
   low[k] = 0;
   high[k] = 0;

   lastVal = FDDL_ARC(k, nodeP, 0);

   for (int i = 0; i < nodeP->size; i++) {
      if (lastVal == FDDL_ARC(k, nodeP, i)) {
         high[k] = i;
      }
      else {
         InternalPrintServiceClasses(k - 1, lastVal, low, high, classNum);
         low[k] = i;
         high[k] = i;
         lastVal = FDDL_ARC(k, nodeP, i);
      }
   }
   InternalPrintServiceClasses(k - 1, FDDL_ARC(k, nodeP, nodeP->size - 1),
                               low, high, classNum);
}

int fw_fddl_forest::GetClasses(mdd_handle p, group ** &output, int numClasses)
{
   int *low;
   int *high;
   if (p.index < 0)
      return INVALID_MDD;
   output = new group *[numClasses];
   for (int i = 1; i < numClasses; i++) {
      output[i] = new group();
      sprintf(output[i]->name, "Class%d", i);
      low = new int[5];
      high = new int[5];
      InternalGetClasses(K, p.index, low, high, i, output[i]);
      delete[]low;
      delete[]high;
   }
   return SUCCESS;
}

void fw_fddl_forest::InternalGetClasses(level k, node_idx p, int *low,
                                        int *high, int classNum, group * head)
{
   if (p == 0 || k == 0) {
      if (p == classNum) {
         address *newAddy;
         newAddy = new address();
         for (int i = 0; i < 4; i++) {
            newAddy->low[3 - i] = k <= i ? low[i + 1] : 0;
            newAddy->high[3 - i] = k <= i ? high[i + 1] : 255;
         }
         newAddy->next = head->list;
         head->list = newAddy;
         return;
      }
      else
         return;
   }


   int lastVal;

   node *nodeP;
   nodeP = &FDDL_NODE(k, p);
   low[k] = 0;
   high[k] = 0;

   lastVal = FDDL_ARC(k, nodeP, 0);

   for (int i = 0; i < nodeP->size; i++) {
      if (lastVal == FDDL_ARC(k, nodeP, i)) {
         high[k] = i;
      }
      else {
         InternalGetClasses(k - 1, lastVal, low, high, classNum, head);
         low[k] = i;
         high[k] = i;
         lastVal = FDDL_ARC(k, nodeP, i);
      }
   }
   InternalGetClasses(k - 1, FDDL_ARC(k, nodeP, nodeP->size - 1), low, high,
                      classNum, head);
}

int fw_fddl_forest::GetServiceArcs(mdd_handle p, int* src, int* dst, service * &output, int& numArcs)
{
   int *low;
   int *high;
   if (p.index < 0)
      return INVALID_MDD;
   output = new service();
   sprintf(output->name, "ServiceGraphArc");
   output->list = NULL;
   low = new int[3];
   high = new int[3];
   for (int i=0;i<3;i++){
      low[i] = high[i] = -1;
   }
   for (level k=K;k>=0;k--)
      FWCache[k]->Clear();
   numArcs = 0;
   InternalGetServiceArcs(K, p.index, src, dst, low, high, output, numArcs);
   delete[]low;
   delete[]high;
   return SUCCESS;
}

int fw_fddl_forest::InternalGetServiceArcs(level k, node_idx p, int* src, int* dst, int* low, int* high, service*& output, int& numArcs){
/*
   char spaces[23];
   for (int i=0;i<K-k;i++){
      spaces[i]=' ';
      spaces[i+1]='\0';
   }
   printf("%s<%d, %d>\n", spaces,k, p);
*/
   
   if (p==0){
      return 0;
   }

   if (k==0){
      return p;
   }

   node* nodeP;
   nodeP = &FDDL_NODE(k,p);
   if (nodeP->size == 0)
      return 0;
   
   if (k==9){
      for (int i=0; i<nodeP->size;i++){
         node_idx q;
         node_idx r;
         q = FDDL_ARC(k,nodeP,i);
         r = InternalGetServiceArcs(k-1, q, src, dst, low, high, output, numArcs);
         if (r == 3){ // If the terminal node is ACCEPT.
            port* newPort;
            newPort = new port();
            newPort->protocol = low[0];
            newPort->low = low[1]*256 + low[2];
            newPort->high = high[1]*256 + high[2];
            newPort->next = output->list;
            output->list = newPort;
            //printf("Adding port: %d[%d]\n", newPort->protocol, newPort->low);
            numArcs++;
            return p;
         }
      }
      return 0;
   }
   if (k<9){
      node_idx r;
      r = FWCache[k]->Hit(p,p);
      if (r >= 0){
         return r;
      }
      for (int i=0; i<nodeP->size;i++){
         node_idx q;
         if (k==7 && i != 1){  //Only look at NEW connections
            continue;
         }
         q = FDDL_ARC(k,nodeP,i);
         if (q == 0)
            continue;
         r = InternalGetServiceArcs(k-1, q, src, dst, low, high, output, numArcs);
         if (r == 3){
            FWCache[k]->Add(p,p,r);
            return r;
         }
      }
      FWCache[k]->Add(p,p,0);
      return 0;
   }
   
   if (k==14){
      for (int i=0;i<nodeP->size;i++){
         node_idx q;
         low[0] = i;
         high[0] = i;
         q = FDDL_ARC(k,nodeP,i);
         if (q != 0)
            InternalGetServiceArcs(k-1, q, src, dst, low, high, output, numArcs);
      }
   }
   else if (k<=11 && k >= 10){
      for (int i=0;i<nodeP->size;i++){
         node_idx q;
         low[12-k] = i;
         high[12-k] = i;
         q = FDDL_ARC(k,nodeP,i);
         if (q != 0)
            InternalGetServiceArcs(k-1, q, src, dst, low, high, output, numArcs);
      }
   }
   else if ((k<=18 && k>=15) || (k<=13 && k>=12)){
      InternalGetServiceArcs(k-1, FDDL_ARC(k,nodeP, dst[18-k]), src,
      dst, low, high, output, numArcs);
   }
   else if (k<=22 & k>=19){
      InternalGetServiceArcs(k-1, FDDL_ARC(k,nodeP, src[22-k]), src,
      dst, low, high, output, numArcs);
   }
   else{
      printf("Error at level %d\n", k);
   }
}

int fw_fddl_forest::GetServiceClasses(mdd_handle p, service ** &output,
                                      int numClasses)
{
   int *low;
   int *high;
   if (p.index < 0)
      return INVALID_MDD;
   output = new service *[numClasses];
   for (int i = 1; i < numClasses; i++) {
      output[i] = new service();
      sprintf(output[i]->name, "Class%d", i);
      low = new int[4];
      high = new int[4];
      InternalGetServiceClasses(K, p.index, low, high, i, output[i]);
      delete[]low;
      delete[]high;
   }
   return SUCCESS;
}

void fw_fddl_forest::InternalGetServiceClasses(level k, node_idx p, int *low,
                                               int *high, int classNum,
                                               service * head)
{
   if (p == 0 || k == 0) {
      if (p == classNum) {
         port *newPort;
         newPort = new port();
         if (k <= 0) {
            newPort->low = low[1];
            newPort->high = high[1];
         }
         else {
            newPort->low = 0;
            newPort->high = 255;
         }

         if (k <= 1) {
            newPort->low += (256 * low[2]);
            newPort->high += (256 * high[2]);
         }
         else {
            newPort->high += (256 * 255);
         }

         if (k <= 2) {
            if (low[3] != high[3])
               newPort->protocol = -1;
            else
               newPort->protocol = high[3];
         }

         newPort->next = head->list;
         head->list = newPort;
         return;
      }
      else
         return;
   }


   int lastVal;

   node *nodeP;
   nodeP = &FDDL_NODE(k, p);
   low[k] = 0;
   high[k] = 0;

   lastVal = FDDL_ARC(k, nodeP, 0);

   for (int i = 0; i < nodeP->size; i++) {
      if (lastVal == FDDL_ARC(k, nodeP, i)) {
         high[k] = i;
      }
      else {
         InternalGetServiceClasses(k - 1, lastVal, low, high, classNum, head);
         low[k] = i;
         high[k] = i;
         lastVal = FDDL_ARC(k, nodeP, i);
      }
   }
   InternalGetServiceClasses(k - 1, FDDL_ARC(k, nodeP, nodeP->size - 1), low,
                             high, classNum, head);
}

