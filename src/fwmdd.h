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


#ifndef SRC_FWMDD_H
#   define SRC_FWMDD_H 1

#   include <iostream>
#   include <assert.h>

#   include <FDDL/mdd.h>
#   include "nat.h"
#   include "structures.h"
#   include "sets.h"
#   include "topology.h"


/*
 * The class fw_fddl_forest enhances the fddl_forest by providing
 * certain algorithms specific to firewall representation.  In 
 * particular, we provide algorithms for query intersection, 
 * NAT transformation of the firewall MDD and 
 * printing Firewall query results.
 */

class chain_rule{
   public:
   int rule_id;
   int chain_id;
   int fw_id;
   chain_rule* next;
};

class fw_fddl_forest:public fddl_forest {
 private:
   cache **FWCache;        //Cache for all firewall specific operations.

 public:

    fw_fddl_forest(int numlevels, int *maxvals):fddl_forest(numlevels, maxvals){

      FWCache = new cache *[K + 4];

      for (int k = 0; k <= K+3; k++) {
         FWCache[k] = new cache;
      } 
   }

   //Clean up data structures used by the forest
   ~fw_fddl_forest() {
      for (level k = K+3; k >= 0; k--) {
         if (FWCache[k])
            delete FWCache[k];
      }
      delete[]FWCache;
   }

   int NumLevels(){ return K; }

   void DisplayElement(mdd_handle p, Topology* T, bool cond);
   int FindElement(mdd_handle p, Topology* T, int*& tup);
   int FindInternalElement(level k, node_idx p, Topology* T, int*& tup);
   node_idx InternalFindElement(level k, node_idx p, int* vals);
   int PrintElement(Topology* T, int* tup);

   int QueryIntersect(mdd_handle p, mdd_handle q, mdd_handle & result);
   node_idx InternalQIntersect(level k, node_idx p, node_idx q);
   int HistoryIntersect(mdd_handle p, mdd_handle q, mdd_handle & result);
   node_idx InternalHIntersect(level k, node_idx p, node_idx q);

   int Accepted(mdd_handle p, mdd_handle & result);
   node_idx InternalAccepted(level k, node_idx p);
   int Dropped(mdd_handle p, mdd_handle & result);
   node_idx InternalDropped(level k, node_idx p);

   int DisplayHistory(mdd_handle root, int* tup);
   int InternalDisplayHistory(level k, node_idx p, int* tup, int chain);

   int PrintHistory(mdd_handle p);
   void InternalPrintHistory(level k, node_idx p, int fw_num, int chain_num, int rule_num);

   chain_rule* GetHistory(mdd_handle p);
   chain_rule* InternalGetHistory(level k, node_idx p, int fw_num, int chain_num, int rule_num, chain_rule* cur);

   int DNAT(mdd_handle p, nat_tuple * pnr, mdd_handle & result);
   node_idx InternalDNAT(level k, node_idx p, node_idx q, nat_tuple * pnr);
   int SNAT(mdd_handle p, nat_tuple * pnr, mdd_handle & result);
   node_idx InternalSNAT(level k, node_idx p, node_idx q, nat_tuple * pnr);
   int NETMAP(mdd_handle p, nat_tuple * pnr, mdd_handle & result);
   node_idx InternalNMAP(level k, node_idx p, node_idx q, nat_tuple * pnr);

   int BuildClassMDD(mdd_handle p, fddl_forest * forest, mdd_handle & r,
                     int &numClasses, int services);

   int InternalBuildClassMDD(fddl_forest * forest, level k, node_idx p,
                             int &numClasses, int services);
  
   int BuildHistoryMDD(mdd_handle p, fw_fddl_forest * forest, mdd_handle & r);
   int InternalBuildHistoryMDD(fw_fddl_forest * forest, level k, node_idx p);

   int BuildServiceGraphMDD(mdd_handle p, fddl_forest * forest, mdd_handle & r,
                     int &numArcs);
   int InternalBuildServiceGraphMDD(fddl_forest * forest, level k, node_idx p,
                             int &numArcs);

   int JoinClasses(mdd_handle p, mdd_handle q, mdd_handle & r,
                   int &outNumClasses);
   node_idx InternalJoinClasses(level k, node_idx p, node_idx q,
                                int &numClasses);

   int PrintClasses(mdd_handle p, int numClasses);
   void InternalPrintClasses(level k, node_idx p, int *low, int *high,
                             int classNum);

   int PrintServiceClasses(mdd_handle p, int numClasses);
   void InternalPrintServiceClasses(level k, node_idx p, int *low, int *high,
                                    int classNum);

   int GetClasses(mdd_handle p, group ** &output, int numClasses);
   void InternalGetClasses(level k, node_idx p, int *low, int *high,
                           int classNum, group * head);

   int GetServiceClasses(mdd_handle p, service ** &output, int numClasses);
   void InternalGetServiceClasses(level k, node_idx p, int *low, int *high,
                                  int classNum, service * head);

   int GetServiceArcs(mdd_handle p, int* src, int* dst, service*&output, int& numArcs);
   int InternalGetServiceArcs(level k, node_idx p, int* src, int* dst,
      int* low, int* high, service*&output, int& numArcs);
  void PrintPort (mdd_handle h, level k);
  int PrintPort (level k, node_idx p, int highByte, int depth, portset * p);

  int IsolateClass(mdd_handle h, int classNum, mdd_handle &r);
  node_idx InternalIsolateClass(level k, node_idx p, int classNum);
  
  int ExpandClass(fw_fddl_forest* forest, mdd_handle h, mdd_handle &r, level top, int serviceFlag);
  node_idx InternalExpandClass(fw_fddl_forest* forest, level k, node_idx p, level top, int serviceFlag);

  int And(mdd_handle a, mdd_handle b, mdd_handle& r);
  node_idx InternalAnd(level k, node_idx a, node_idx b);
};

#endif
