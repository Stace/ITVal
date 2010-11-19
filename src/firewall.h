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
#include "fwmdd.h"
#include "topology.h"
#include "structures.h"

class Firewall {
   int num_chains;
   int num_nat_chains;

   //Can handle up to 256 seperate chains per firewall.
   chain *chain_array[256];
   nat_chain *nat_chains[256];

   //Linked lists of processed(netmasks->ranges, strings->values) rules.
   processed_rule *phead;
   processed_nat_rule *natHead;

   void ReadChain(char *line, ssize_t length, chain * newChain);
   void BuildFWRules(char *fname);
   void BuildVerboseFWRules(char *fname);
   void BuildNATRules(char *fname);
   void BuildChains(int input_chain, mdd_handle & outputMDD,
                    mdd_handle & logMDD, mdd_handle & outHistMDD);

   void AssembleChains(chain ** chain_array, chain * ch, mdd_handle & outMDD,
                       mdd_handle & logMDD, mdd_handle & outHistMDD);

   void ProcessChain(chain ** chain_array, mdd_handle inMDD, mdd_handle inHistMDD, rule_tuple * tup,
                     mdd_handle & outMDD, mdd_handle & logMDD,  mdd_handle & outHistMDD);

   void BuildRules(processed_rule * pr, rule_tuple * &tup);

   void DoDestLeft(processed_rule * pr, rule_tuple * tup, rule_tuple * &stack, int i, int* L, int* H);
   void DoDestRight(processed_rule * pr, rule_tuple * tup, rule_tuple * &stack, int i, int* L, int* H);
   void DoSrcLeft(processed_rule * pr, rule_tuple * tup, rule_tuple * &stack, int i, int* L, int* H);
   void DoSrcRight(processed_rule * pr, rule_tuple * tup, rule_tuple * &stack, int i, int* L, int* H);
   void DoSrcMiddle(processed_rule * pr, rule_tuple * tup, rule_tuple * &stack, int i);
   void DoDestMiddle(processed_rule * pr, rule_tuple * tup, rule_tuple * &stack, int i);

   void ProcessSource(processed_rule * pr, rule_tuple * tup,
                      rule_tuple * &stack);
   void ProcessDest(processed_rule * pr, rule_tuple * tup,
                    rule_tuple * &stack);
   void ProcessInverseSource(address_range * cur, processed_rule * pr, rule_tuple * tup,
                      rule_tuple * &stack);
   void ProcessInverseDest(address_range * cur, processed_rule * pr, rule_tuple * tup,
                    rule_tuple * &stack);
   void ProcessProt(processed_rule * pr, rule_tuple * tup,
                    rule_tuple * &stack);
   void ProcessSport(processed_rule * pr, rule_tuple * tup,
                     rule_tuple * &stack);
   void ProcessDport(processed_rule * pr, rule_tuple * tup,
                     rule_tuple * &stack);
   void ProcessIfaces(processed_rule * pr, rule_tuple * tup,
                      rule_tuple * &stack);
   void ProcessState(processed_rule * pr, rule_tuple * tup,
                     rule_tuple * &stack);
   void ProcessFlags(processed_rule * pr, rule_tuple * tup,
                     rule_tuple * &stack);
   void ProcessTarget(processed_rule * pr, rule_tuple * tup,
                      rule_tuple * &stack);

   void ConvertNATRules(processed_nat_rule * pnr, nat_tuple * &stack);
   void DoNAT(nat_tuple * tup, mdd_handle inMDD, mdd_handle inHistMDD, mdd_handle & outMDD, mdd_handle & logMDD, mdd_handle & outHistMDD);

   void ProcessNATSource(processed_nat_rule * pr, nat_tuple * tup,
                         nat_tuple * &stack);
   void ProcessNATDest(processed_nat_rule * pr, nat_tuple * tup,
                       nat_tuple * &stack);
   void ProcessNATProt(processed_nat_rule * pr, nat_tuple * tup,
                       nat_tuple * &stack);
   void ProcessNATSport(processed_nat_rule * pr, nat_tuple * tup,
                        nat_tuple * &stack);
   void ProcessNATDport(processed_nat_rule * pr, nat_tuple * tup,
                        nat_tuple * &stack);
   void ProcessNATState(processed_nat_rule * pr, nat_tuple * tup,
                        nat_tuple * &stack);
   void ProcessNATFlags(processed_nat_rule * pr, nat_tuple * tup,
                        nat_tuple * &stack);
   void ProcessNATTarget(processed_nat_rule * pr, nat_tuple * tup,
                         nat_tuple * &stack);

 public:
   Topology * T;
   fw_fddl_forest *FWForest;
   fw_fddl_forest *ClassForest;
   fw_fddl_forest *ServiceClassForest;
   fw_fddl_forest *HistoryForest;
   mdd_handle Input;
   mdd_handle InputHist;
   mdd_handle InputLog;
   mdd_handle Output;
   mdd_handle OutputHist;
   mdd_handle OutputLog;
   mdd_handle Forward;
   mdd_handle ForwardHist;
   mdd_handle ForwardLog;

   int FindChain(char *name);
   int FindNATChain(char *name);
   void NATChains(int input_chain, mdd_handle inMDD, mdd_handle inHistMDD, mdd_handle & outMDD,
                  mdd_handle & logMDD, mdd_handle & outHistMDD);

     Firewall(fw_fddl_forest * F, fw_fddl_forest * H);

     Firewall(char *filterName, char *natName, fw_fddl_forest * F,
              Topology * top, fw_fddl_forest * H);
     Firewall(char *filterName, char *natName, fw_fddl_forest * F,
              Topology * top, int verbose, fw_fddl_forest * H);

   ~Firewall();
   int PrintClasses();
   int PrintServiceClasses();
   int GetClasses(group ** &Classes, int &numClasses);
   int GetServiceClasses(service ** &Classes, int &numClasses);
   int GetServiceGraph(int* src, int* dst, service* &arcs, int& numArcs);
};

/* Create a META-Firewall from all the independent firewalls.*/
Firewall *MergeFWs(fw_fddl_forest * FWForest, Firewall ** fws, int num_fws, fw_fddl_forest * HForest);
Topology *MergeTopology(Topology * curTop, Topology * newTop);
