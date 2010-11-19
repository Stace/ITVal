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
#include "firewall.h"

Firewall::Firewall(fw_fddl_forest * F, fw_fddl_forest * H, int id_num)
{
   int ranges[5] = { 65536, 255, 255, 255, 255 };
   FWForest = F;
   HistoryForest = H;
   num_nat_chains = -1;
   num_chains = -1;
   id = id_num;
   for (int i = 0; i < 256; i++) {
      chain_array[i] = nat_chains[i] = NULL;
   }
   ClassForest = new fw_fddl_forest(5, ranges);
   ClassForest->ToggleSparsity(false);
   ranges[3] = 2; //Right?
   ranges[2] = 255;
   ranges[1] = 255;
   ServiceClassForest = new fw_fddl_forest(4, ranges);
   ServiceClassForest->ToggleSparsity(false);
   natHead = NULL;
};

Firewall::Firewall(char *filterName, char *natName, fw_fddl_forest * F,
                   Topology * top, fw_fddl_forest *H, int id_num)
{
   int ranges[5] = { 65536, 256, 256, 256, 256 };
   int high[TOP_LEVEL+1];
   int low[TOP_LEVEL+1];

   int input_chain;
   int forward_chain;
   int output_chain;

   id = id_num;

   FWForest = F;
   HistoryForest = H;
   T = top;
   
   num_nat_chains = -1;
   num_chains = -1;
   for (int i = 0; i < 256; i++) {
      chain_array[i] = nat_chains[i] = NULL;
   }

   // Create and Initialize the Log MDDs
   for (level k = 0; k <= TOP_LEVEL; k++) {
      low[k] = 0;
      high[k] = F->GetMaxVal(k);
   }
   high[0] = 0;

   FWForest->MakeMDDFromTuple(low, high, InputLog);
   FWForest->MakeMDDFromTuple(low, high, OutputLog);
   FWForest->MakeMDDFromTuple(low, high, ForwardLog);

   BuildFWRules(filterName);

   if (strncmp(natName, "NONAT", 5)) {
      BuildNATRules(natName);
   }
   forward_chain = FindChain("FORWARD");
   input_chain = FindChain("INPUT");
   output_chain = FindChain("OUTPUT");
   if (forward_chain < 0) {
      printf("No Forward Chain!\n");
      exit(-1);
   }
   if (input_chain < 0) {
      printf("No Input Chain!\n");
      exit(-1);
   }
   if (output_chain < 0) {
      printf("No Output Chain!\n");
      exit(-1);
   }

   BuildChains(forward_chain, Forward, ForwardLog, ForwardHist);
   BuildChains(input_chain, Input, InputLog, InputHist);
   BuildChains(output_chain, Output, OutputLog, OutputHist);
   ClassForest = new fw_fddl_forest(5, ranges);
   ClassForest->ToggleSparsity(false);
   ranges[3] = 2; //Right?
   ranges[2] = 255;
   ranges[1] = 255;
   ServiceClassForest = new fw_fddl_forest(4, ranges);
   ServiceClassForest->ToggleSparsity(false);
   natHead = NULL;
}

Firewall::Firewall(char *filterName, char *natName, fw_fddl_forest * F,
                   Topology * top, int verbose, fw_fddl_forest * H, int id_num)
{
   int ranges[5] = { 65536, 255, 255, 255, 255 };
   int high[TOP_LEVEL+1];
   int low[TOP_LEVEL+1];

   int input_chain;
   int forward_chain;
   int output_chain;

   id = id_num;
   FWForest = F;
   T = top;

   HistoryForest = H;
   num_nat_chains = -1;
   num_chains = -1;
   for (int i = 0; i < 256; i++) {
      chain_array[i] = nat_chains[i] = NULL;
   }

   // Create and Initialize the Log MDDs
   for (level k = 0; k <= TOP_LEVEL; k++) {
      low[k] = 0;
      high[k] = F->GetMaxVal(k);
   }
   high[0] = 0;

   FWForest->MakeMDDFromTuple(low, high, InputLog);
   FWForest->MakeMDDFromTuple(low, high, OutputLog);
   FWForest->MakeMDDFromTuple(low, high, ForwardLog);

   BuildVerboseFWRules(filterName);
   if (strncmp(natName, "NONAT", 5)) {
      BuildNATRules(natName);
   }
   forward_chain = FindChain("FORWARD");
   input_chain = FindChain("INPUT");
   output_chain = FindChain("OUTPUT");
   if (forward_chain < 0) {
      printf("No Forward Chain!\n");
      exit(-1);
   }
   if (input_chain < 0) {
      printf("No Input Chain!\n");
      exit(-1);
   }
   if (output_chain < 0) {
      printf("No Output Chain!\n");
      exit(-1);
   }

   BuildChains(forward_chain, Forward, ForwardLog, ForwardHist);
   BuildChains(input_chain, Input, InputLog, InputHist);
   BuildChains(output_chain, Output, OutputLog, OutputHist);

#ifdef DEBUG
   printf("Forward:%d Input:%d Output:%d\n", Forward.index, Input.index, Output.index);
   for (level k = TOP_LEVEL; k > 0; k--)
      FWForest->Compact(k);
   FWForest->PrintMDD();
#endif 
#ifdef DEBUG
   printf("ForwardHist: %d InputHist: %d OutputHist %d\n", ForwardHist.index, InputHist.index, OutputHist.index);
   for (level k = 24; k > 0; k--){
      HistoryForest->Compact(k);
   }
   HistoryForest->PrintMDD();
#endif
   ClassForest = new fw_fddl_forest(5, ranges);
   ClassForest->ToggleSparsity(false);
   ranges[3] = 2; //Right?
   ranges[2] = 255;
   ranges[1] = 255;
   ServiceClassForest = new fw_fddl_forest(4, ranges);
   ServiceClassForest->ToggleSparsity(false);
   natHead = NULL;
}

Firewall::~Firewall() {
      while (natHead != NULL) {
         processed_nat_rule *cur;
           cur = natHead;
           natHead = (processed_nat_rule *) natHead->next;
         delete cur;
      } for (int i = 0; i < num_chains; i++)
         if (chain_array[i] != NULL)
            delete chain_array[i];

      for (int i = 0; i < num_nat_chains; i++)
         if (nat_chains[i] != NULL)
            delete nat_chains[i];

      FWForest->DestroyMDD(Input);
      FWForest->DestroyMDD(Output);
      FWForest->DestroyMDD(Forward);
      HistoryForest->DestroyMDD(InputHist);
      HistoryForest->DestroyMDD(OutputHist);
      HistoryForest->DestroyMDD(ForwardHist);
      FWForest->DestroyMDD(InputLog);
      FWForest->DestroyMDD(OutputLog);
      FWForest->DestroyMDD(ForwardLog);

      delete ClassForest;
      delete ServiceClassForest;
      if (T)
         delete T;
      T = NULL;
   }


int Firewall::PrintClasses(int history)
{
   mdd_handle FWSourceClass;
   mdd_handle INSourceClass;
   mdd_handle OUTSourceClass;

   mdd_handle FWDestClass;
   mdd_handle INDestClass;
   mdd_handle OUTDestClass;

   mdd_handle newChain;
   mdd_handle resultClass;

   int numClasses = 0;

   FWForest->BuildClassMDD(Forward, ClassForest, FWSourceClass, numClasses, 0);

//   printf("There are %d Forward Source classes:\n", numClasses);
//   ClassForest->PrintMDD();
//   ClassForest->PrintClasses(FWSourceClass, numClasses);
   
   FWForest->BuildClassMDD(Input, ClassForest, INSourceClass, numClasses, 0);
   
//   printf("There are %d Input Source classes:\n", numClasses);
   //ClassForest->PrintMDD();
//   ClassForest->PrintClasses(INSourceClass, numClasses);
   
   FWForest->BuildClassMDD(Output, ClassForest, OUTSourceClass, numClasses,
                           0);
//   printf("There are %d Output Source classes:\n", numClasses);
   //ClassForest->PrintMDD();
//   ClassForest->PrintClasses(OUTSourceClass, numClasses);

   //Shift Destination Addresses to Top.
   FWForest->Shift(Forward, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   
// As we move lower levels to the top, the top levels move down!
//   FWForest->Shift(newChain,16,newChain);
//   FWForest->Shift(newChain,17,newChain);
//   FWForest->Shift(newChain,18,newChain);


   FWForest->BuildClassMDD(newChain, ClassForest, FWDestClass, numClasses, 0);

   //Debug
//   printf("There are %d Forward Destination classes:\n", numClasses);
//   ClassForest->PrintClasses(FWDestClass, numClasses);
//   printf("FWDestClass: %d\n", FWDestClass.index);
//   ClassForest->PrintMDD();
   //End Debug

   FWForest->Shift(Input, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->BuildClassMDD(newChain, ClassForest, INDestClass, numClasses, 0);
//   printf("There are %d Input Destination classes:\n", numClasses);
//   ClassForest->PrintMDD();
//   ClassForest->PrintClasses(INDestClass, numClasses);

   FWForest->Shift(Output, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->BuildClassMDD(newChain, ClassForest, OUTDestClass, numClasses,
                           0);
//   printf("There are %d Output Destination classes:\n", numClasses);
   //ClassForest->PrintMDD();
//   ClassForest->PrintClasses(OUTDestClass, numClasses);

   ClassForest->JoinClasses(FWSourceClass, INSourceClass, resultClass,
                            numClasses);

   ClassForest->JoinClasses(resultClass, OUTSourceClass, resultClass,
                            numClasses);

//   printf("Join Result and OUTSource: \n");
//   ClassForest->PrintClasses(resultClass, numClasses);

   ClassForest->JoinClasses(resultClass, FWDestClass, resultClass,
                            numClasses);
   ClassForest->JoinClasses(resultClass, INDestClass, resultClass,
                            numClasses);
   ClassForest->JoinClasses(resultClass, OUTDestClass, resultClass,
                            numClasses);

   printf("There are %d total host classes:\n", numClasses-1);
   ClassForest->PrintClasses(resultClass, numClasses);
   if (history)
      PrintClassHistory(resultClass, numClasses);
}

int Firewall::PrintClassHistory(mdd_handle classMDD, int numClasses){
   int i;
   chain_rule* results;
   mdd_handle newClass;
   mdd_handle sourceHistory;
   mdd_handle destinationHistory;
   mdd_handle result;
   bool resultsFound;
   for (i=1;i<numClasses;i++){
      printf("Class %d:\n", i);
      ClassForest->IsolateClass(classMDD,i,newClass); 
      HistoryForest->ExpandClass(ClassForest,newClass,sourceHistory,25,0); 
      HistoryForest->ExpandClass(ClassForest,newClass,destinationHistory,21,0); 

      HistoryForest->And(sourceHistory, InputHist, result);
      results = HistoryForest->GetHistory(result);
      resultsFound = false;
      while (results != NULL){
         DisplayRule(results->fw_id, results->chain_id, results->rule_id);
         results = results->next;
	 resultsFound = true;
      }


      HistoryForest->And(sourceHistory, ForwardHist, result);
      results = HistoryForest->GetHistory(result);
      while (results != NULL){
         DisplayRule(results->fw_id, results->chain_id, results->rule_id);
         results = results->next;
	 resultsFound = true;
      }

      HistoryForest->And(sourceHistory, OutputHist, result);
      results = HistoryForest->GetHistory(result);
      while (results != NULL){
         DisplayRule(results->fw_id, results->chain_id, results->rule_id);
         results = results->next;
	 resultsFound = true;
      } 
      if (!resultsFound)
	 printf("No rules matched!\n");
      printf("\n");
   }
   //HistoryForest->PruneMDD(sourceHistory);
   //   for (int k=25;k>0;k--)
   //      HistoryForest->Compact(k);
   //   HistoryForest->PrintMDD();
}

int Firewall::PrintServiceClassHistory(mdd_handle classMDD, int numClasses){
   int i;
   chain_rule* results;
   mdd_handle newClass;
   mdd_handle sourceHistory;
   mdd_handle destinationHistory;
   mdd_handle result;
   bool resultsFound;
   for (i=1;i<numClasses;i++){
      printf("Class %d:\n", i);
      ServiceClassForest->IsolateClass(classMDD,i,newClass); 

      HistoryForest->ExpandClass(ServiceClassForest,newClass,sourceHistory,14,1); 
      HistoryForest->ExpandClass(ServiceClassForest,newClass,destinationHistory,14,2); 
      //printf("sourceHistory: %d\n", sourceHistory.index);
      //printf("sourceHistory: %d\n", destinationHistory.index);
      //HistoryForest->PrintMDD();

      HistoryForest->And(sourceHistory, InputHist, result);
      results = HistoryForest->GetHistory(result);
      resultsFound = false;
      while (results != NULL){
         DisplayRule(results->fw_id, results->chain_id, results->rule_id);
         results = results->next;
	 resultsFound = true;
      }


      HistoryForest->And(sourceHistory, ForwardHist, result);
      results = HistoryForest->GetHistory(result);
      while (results != NULL){
         DisplayRule(results->fw_id, results->chain_id, results->rule_id);
         results = results->next;
	 resultsFound = true;
      }

      HistoryForest->And(sourceHistory, OutputHist, result);
      results = HistoryForest->GetHistory(result);
      while (results != NULL){
         DisplayRule(results->fw_id, results->chain_id, results->rule_id);
         results = results->next;
	 resultsFound = true;
      } 
      if (!resultsFound)
	 printf("No rules matched!\n");
      printf("\n");
   }
   //HistoryForest->PruneMDD(sourceHistory);
   //   for (int k=25;k>0;k--)
   //      HistoryForest->Compact(k);
   //   HistoryForest->PrintMDD();
}

int Firewall::GetClasses(group ** &classes, int &numClasses)
{
   mdd_handle FWSourceClass;
   mdd_handle INSourceClass;
   mdd_handle OUTSourceClass;

   mdd_handle FWDestClass;
   mdd_handle INDestClass;
   mdd_handle OUTDestClass;

   mdd_handle newChain;
   mdd_handle resultClass;

   numClasses = 0;

   FWForest->BuildClassMDD(Forward, ClassForest, FWSourceClass, numClasses,
                           0);
   FWForest->BuildClassMDD(Input, ClassForest, INSourceClass, numClasses, 0);
   FWForest->BuildClassMDD(Output, ClassForest, OUTSourceClass, numClasses,
                           0);

   //Shift Destination Addresses to Top.
   FWForest->Shift(Forward, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);

   FWForest->BuildClassMDD(newChain, ClassForest, FWDestClass, numClasses, 0);
   FWForest->Shift(Input, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->BuildClassMDD(newChain, ClassForest, INDestClass, numClasses, 0);
   FWForest->Shift(Output, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->Shift(newChain, 15, newChain);
   FWForest->BuildClassMDD(newChain, ClassForest, OUTDestClass, numClasses,
                           0);

   ClassForest->JoinClasses(FWSourceClass, INSourceClass, resultClass,
                            numClasses);
   ClassForest->DestroyMDD(FWSourceClass);
   ClassForest->DestroyMDD(INSourceClass);
   ClassForest->JoinClasses(resultClass, OUTSourceClass, resultClass,
                            numClasses);
   ClassForest->DestroyMDD(OUTSourceClass);
   ClassForest->JoinClasses(resultClass, FWDestClass, resultClass,
                            numClasses);
   ClassForest->DestroyMDD(FWDestClass);
   ClassForest->JoinClasses(resultClass, INDestClass, resultClass,
                            numClasses);
   ClassForest->DestroyMDD(INDestClass);
   ClassForest->JoinClasses(resultClass, OUTDestClass, resultClass,
                            numClasses);
   ClassForest->DestroyMDD(OUTDestClass);

   for (level k = 4; k > 0; k--)
      ClassForest->Compact(k);
//   printf("There are %d total host classes:\n",numClasses);
//   ClassForest->PrintMDD();
//   ClassForest->PrintClasses(resultClass, numClasses);

   classes = NULL;
   if (ClassForest->GetClasses(resultClass, classes, numClasses) == SUCCESS)
      return 1;
   return 0;
}

int Firewall::GetServiceGraph(int* src, int* dst, service*& arcs, int& numArcs){
   mdd_handle FWSourceClass;
   mdd_handle INSourceClass;
   mdd_handle OUTSourceClass;

   mdd_handle FWDestClass;
   mdd_handle INDestClass;
   mdd_handle OUTDestClass;

   mdd_handle newChain;
   mdd_handle resultClass;
/*
   FWForest->Shift(Forward, 12, newChain);      //Grab source port byte 2
   FWForest->Shift(newChain, 12, newChain);     //Grab source port byte 1
   FWForest->Shift(newChain, 12, FWSourceClass);     //Grab protocol

   FWForest->Shift(Input, 12, newChain);        //Grab source port byte 2
   FWForest->Shift(newChain, 12, newChain);     //Grab source port byte 1
   FWForest->Shift(newChain, 12, INSourceClass);     //Grab protocol
   
   FWForest->Shift(Output, 12, newChain);       //Grab source port byte 2
   FWForest->Shift(newChain, 12, newChain);     //Grab source port byte 1
   FWForest->Shift(newChain, 12, OUTSourceClass);     //Grab protocol
   
   //Shift Destination Port to Top.
   FWForest->Shift(Forward, 10, newChain);      //Grab destination port byte 2
   FWForest->Shift(newChain, 10, newChain);     //Grab destination port byte 1
   FWForest->Shift(newChain, 12, FWDestClass);     //Grab protocol
   

   FWForest->Shift(Input, 10, newChain);
   FWForest->Shift(newChain, 10, newChain);
   FWForest->Shift(newChain, 12, INDestClass);

   FWForest->Shift(Output, 10, newChain);
   FWForest->Shift(newChain, 10, newChain);
   FWForest->Shift(newChain, 12, OUTDestClass);

   FWForest->Max(FWSourceClass, INSourceClass, resultClass);

   FWForest->DestroyMDD(FWSourceClass);
   FWForest->DestroyMDD(INSourceClass);

   FWForest->Max(resultClass, OUTSourceClass, resultClass);
   FWForest->DestroyMDD(OUTSourceClass);

   FWForest->Max(resultClass, FWDestClass, resultClass);
   FWForest->DestroyMDD(FWDestClass);

   FWForest->Max(resultClass, INDestClass, resultClass);
   FWForest->DestroyMDD(INDestClass);

   FWForest->Max(resultClass, OUTDestClass, resultClass);                                   
   FWForest->DestroyMDD(OUTDestClass);
*/
   //FWForest->Max(Forward, Input, resultClass);
   //FWForest->Max(resultClass, Output, resultClass);
   
   if (FWForest->
       GetServiceArcs(Forward, src, dst, arcs, numArcs) == SUCCESS)
      return 1;
   return 0;
}

int Firewall::PrintServiceClasses(int history)
{
   int numClasses;

   mdd_handle FWSourceClass;
   mdd_handle INSourceClass;
   mdd_handle OUTSourceClass;

   mdd_handle FWDestClass;
   mdd_handle INDestClass;
   mdd_handle OUTDestClass;

   mdd_handle newChain;
   mdd_handle resultClass;

/*
   for (level k=3;k>0;k--)
      ServiceClassForest->Compact(k);
   printf("There are %d total service classes:\n",numClasses);
   ServiceClassForest->PrintMDD();
*/
/*
   for (level k=TOP_LEVEL+1;k>0;k--)
      FWForest->Compact(k);
   FWForest->PrintMDD();
*/

   numClasses = 0;
   FWForest->Shift(Forward, 12, newChain);      //Grab source port byte 2
   FWForest->Shift(newChain, 12, newChain);     //Grab source port byte 1
   FWForest->Shift(newChain, 12, newChain);     //Grab protocol
   FWForest->BuildClassMDD(newChain, ServiceClassForest, FWSourceClass,
                           numClasses, 1);

   FWForest->Shift(Input, 12, newChain);        //Grab source port byte 2
   FWForest->Shift(newChain, 12, newChain);     //Grab source port byte 1
   FWForest->Shift(newChain, 12, newChain);     //Grab protocol
   FWForest->BuildClassMDD(newChain, ServiceClassForest, INSourceClass,
                           numClasses, 1);
   
   FWForest->Shift(Output, 12, newChain);       //Grab destination port byte 2
   FWForest->Shift(newChain, 12, newChain);     //Grab destination port byte 1
   FWForest->Shift(newChain, 12, newChain);     //Grab protocol
   FWForest->BuildClassMDD(newChain, ServiceClassForest, OUTSourceClass,
                           numClasses, 1);
   
   //Shift Destination Port to Top.
   FWForest->Shift(Forward, 10, newChain);      //Grab destination port byte 2
   FWForest->Shift(newChain, 10, newChain);     //Grab destination port byte 1
   FWForest->Shift(newChain, 12, newChain);     //Grab protocol
   FWForest->BuildClassMDD(newChain, ServiceClassForest, FWDestClass,
                           numClasses, 1);
   
   FWForest->Shift(Input, 10, newChain);
   FWForest->Shift(newChain, 10, newChain);
   FWForest->Shift(newChain, 12, newChain);
   FWForest->BuildClassMDD(newChain, ServiceClassForest, INDestClass,
                           numClasses, 1);
   
   FWForest->Shift(Output, 10, newChain);
   FWForest->Shift(newChain, 10, newChain);
   FWForest->Shift(newChain, 12, newChain);
   FWForest->BuildClassMDD(newChain, ServiceClassForest, OUTDestClass,
                           numClasses, 1);


   ServiceClassForest->JoinClasses(FWSourceClass, INSourceClass, resultClass,
                                   numClasses);
   ServiceClassForest->DestroyMDD(FWSourceClass);
   ServiceClassForest->DestroyMDD(INSourceClass);

   ServiceClassForest->JoinClasses(resultClass, OUTSourceClass, resultClass,
                                   numClasses);
   ServiceClassForest->DestroyMDD(OUTSourceClass);

   ServiceClassForest->JoinClasses(resultClass, FWDestClass, resultClass,
                                   numClasses);
   ServiceClassForest->DestroyMDD(FWDestClass);

   ServiceClassForest->JoinClasses(resultClass, INDestClass, resultClass,
                                   numClasses);
   ServiceClassForest->DestroyMDD(INDestClass);

   ServiceClassForest->JoinClasses(resultClass, OUTDestClass, resultClass,
                                   numClasses);
   ServiceClassForest->DestroyMDD(OUTDestClass);

   printf("There are %d total service classes:\n", numClasses-1);
   ServiceClassForest->PrintServiceClasses(resultClass, numClasses);
   if (history)
      PrintServiceClassHistory(resultClass, numClasses);
   return 1;
}

int Firewall::GetServiceClasses(service ** &classes, int &numClasses)
{
   mdd_handle FWSourceClass;
   mdd_handle INSourceClass;
   mdd_handle OUTSourceClass;

   mdd_handle FWDestClass;
   mdd_handle INDestClass;
   mdd_handle OUTDestClass;

   mdd_handle newChain;
   mdd_handle resultClass;

   numClasses = 0;

   FWForest->Shift(Forward, 12, newChain);      //Grab source port byte 2
   FWForest->Shift(newChain, 12, newChain);     //Grab source port byte 1
   FWForest->Shift(newChain, 12, newChain);     //Grab protocol
   FWForest->BuildClassMDD(Forward, ServiceClassForest, FWSourceClass,
                           numClasses, 1);

   FWForest->Shift(Input, 12, newChain);        //Grab source port byte 2
   FWForest->Shift(newChain, 12, newChain);     //Grab source port byte 1
   FWForest->Shift(newChain, 12, newChain);     //Grab protocol
   FWForest->BuildClassMDD(Input, ServiceClassForest, INSourceClass,
                           numClasses, 1);

   FWForest->Shift(Output, 12, newChain);       //Grab source port byte 2
   FWForest->Shift(newChain, 12, newChain);     //Grab source port byte 1
   FWForest->Shift(newChain, 12, newChain);     //Grab protocol
   FWForest->BuildClassMDD(Output, ServiceClassForest, OUTSourceClass,
                           numClasses, 1);

   //Shift Destination Port to Top.
   FWForest->Shift(Forward, 10, newChain);      //Grab destination port byte 2
   FWForest->Shift(newChain, 10, newChain);     //Grab destination port byte 1
   FWForest->Shift(newChain, 20, newChain);     //Grab protocol
   FWForest->BuildClassMDD(newChain, ServiceClassForest, FWDestClass,
                           numClasses, 1);

   FWForest->Shift(Input, 10, newChain);
   FWForest->Shift(newChain, 10, newChain);
   FWForest->Shift(newChain, 20, newChain);
   FWForest->BuildClassMDD(newChain, ServiceClassForest, INDestClass,
                           numClasses, 1);

   FWForest->Shift(Output, 10, newChain);
   FWForest->Shift(newChain, 10, newChain);
   FWForest->Shift(newChain, 20, newChain);
   FWForest->BuildClassMDD(newChain, ServiceClassForest, OUTDestClass,
                           numClasses, 1);

//   for (level k=3;k>0;k--)
//      ClassForest->Compact(k);
//   printf("There are %d total service classes:\n",numClasses);
//   ClassForest->PrintMDD();

   ServiceClassForest->JoinClasses(FWSourceClass, INSourceClass, resultClass,
                                   numClasses);
   ServiceClassForest->DestroyMDD(FWSourceClass);
   ServiceClassForest->DestroyMDD(INSourceClass);

   ServiceClassForest->JoinClasses(resultClass, OUTSourceClass, resultClass,
                                   numClasses);
   ServiceClassForest->DestroyMDD(OUTSourceClass);

   ServiceClassForest->JoinClasses(resultClass, FWDestClass, resultClass,
                                   numClasses);
   ServiceClassForest->DestroyMDD(FWDestClass);

   ServiceClassForest->JoinClasses(resultClass, INDestClass, resultClass,
                                   numClasses);
   ServiceClassForest->DestroyMDD(INDestClass);

   ServiceClassForest->JoinClasses(resultClass, OUTDestClass, resultClass,
                                   numClasses);
   ServiceClassForest->DestroyMDD(OUTDestClass);

//   for (level k=3;k>0;k--)
//      ClassForest->Compact(k);
//   printf("There are %d total service classes:\n",numClasses);
//   ClassForest->PrintMDD();

   classes = NULL;
   if (ServiceClassForest->
       GetServiceClasses(resultClass, classes, numClasses) == SUCCESS)
      return 1;
   return 0;
}

/* Create a Meta-Firewall */
/* Need to do something about Topologies, here. */
Firewall *MergeFWs(fw_fddl_forest * FWForest, Firewall ** fws, int n, fw_fddl_forest * HistoryForest)
{
   Topology* tmp;
   Firewall *f;
   int prerouting, postrouting;

   int i = 0;

   if (n == 0)
      return NULL;

   f = new Firewall(FWForest, HistoryForest, -1);
   // Copy Rule Tuples into Merged Firewall
   f->merged_chains = new chain**[n];
   for (i=0;i<n;i++){
      f->merged_chains[fws[i]->id] = new chain*[256];
      for (int j=0;j<256;j++){
         if (fws[i]->id <0 || fws[i]->id > n)
	    continue;
         f->merged_chains[fws[i]->id][j] = fws[i]->chain_array[j];
      }
   }

   prerouting = fws[0]->FindNATChain("Prerouting");
   postrouting = fws[0]->FindNATChain("Postrouting");

   if (prerouting >= 0) {
      fws[0]->NATChains(postrouting, fws[0]->Forward, fws[0]->ForwardHist, f->Forward, f->ForwardLog, f->ForwardHist);
      fws[0]->NATChains(postrouting, fws[0]->Input, fws[0]->InputHist, f->Input, f->InputLog, f->InputHist);
      fws[0]->NATChains(postrouting, fws[n - 1]->Output, fws[n - 1]->OutputHist, f->Output, f->OutputLog, f->OutputHist);
   }
   else {
      FWForest->Attach(f->Forward, fws[0]->Forward.index);
      HistoryForest->Attach(f->ForwardHist, fws[0]->ForwardHist.index);
      FWForest->Attach(f->ForwardLog, fws[0]->ForwardLog.index);

      FWForest->Attach(f->Input, fws[0]->Input.index);
      HistoryForest->Attach(f->InputHist, fws[0]->InputHist.index);
      FWForest->Attach(f->InputLog, fws[0]->InputLog.index);

      FWForest->Attach(f->Output, fws[n - 1]->Output.index);
      HistoryForest->Attach(f->OutputHist, fws[n - 1]->OutputHist.index);
      FWForest->Attach(f->OutputLog, fws[n - 1]->OutputLog.index);
   }

   for (i = 1; i < n; i++) {
      FWForest->Min(f->Forward, fws[i]->Forward, f->Forward);
      FWForest->Min(f->Input, fws[i]->Forward, f->Forward);
      FWForest->Min(f->Output, fws[(n - 1) - i]->Forward, f->Forward);

      HistoryForest->Min(f->ForwardHist, fws[i]->ForwardHist, f->ForwardHist);
      HistoryForest->Min(f->InputHist, fws[i]->ForwardHist, f->ForwardHist);
      HistoryForest->Min(f->OutputHist, fws[(n - 1) - i]->ForwardHist, f->ForwardHist);

      prerouting = fws[i]->FindNATChain("Prerouting");
      postrouting = fws[i - 1]->FindNATChain("Postrouting");

      /* SNAT the chains (and postrouting NETMAP them) */
      if (postrouting >= 0) {
         fws[i]->NATChains(postrouting, f->Forward, f->ForwardHist, f->Forward,
                           f->ForwardLog, f->ForwardHist);
         fws[i]->NATChains(postrouting, f->Input, f->InputHist,f->Input, f->InputLog,f->InputHist);
      }
      /* DNAT the chains and (Prerouting NETMAP them) */
      if (prerouting >= 0) {
         fws[i]->NATChains(prerouting, f->Forward, f->ForwardHist, f->Forward, f->ForwardLog, f->ForwardHist);
         fws[i]->NATChains(prerouting, f->Input, f->InputHist, f->Input, f->InputLog, f->InputHist);
      }

      prerouting = fws[(n - 1) - i]->FindNATChain("Prerouting");
      postrouting = fws[n - i]->FindNATChain("Postrouting");
      if (postrouting >= 0) {
         fws[n - i]->NATChains(postrouting, f->Output, f->OutputHist, f->Output,
                               f->OutputLog, f->OutputHist);
      }
      if (prerouting >= 0) {
         fws[n - i]->NATChains(prerouting, f->Output, f->OutputHist, f->Output,
                               f->OutputLog, f->OutputHist);
      }
   }

   f->T = NULL;
   for (i = 0; i < n; i++) {
      tmp = MergeTopology(f->T, fws[i]->T);
      if (f->T)
         delete f->T;
      f->T = tmp;
   }
   return f;
}

/*@BUG@ Fix to really merge these babies!!!! */
Topology *MergeTopology(Topology * curTop, Topology * newTop)
{
   Topology *newT;
   newT = new Topology();
   newT->numIfaces = 0;
   if (newTop == NULL){
      delete newT;
      return NULL;
      //return newT;
   }
   for (int i = 0; i < newTop->numIfaces; i++) {
      if (newTop->ifaces[i] != NULL){
         printf("Copying %s\n", newTop->ifaces[i]->name);
         newT->ifaces[i] = new Interface(newTop->ifaces[i]->name, newTop->ifaces[i]->ip);
         newT->numIfaces++;
      }
   }
   return newT;
}

int Firewall::DisplayRule(int fw_id, int chain_id, int rule_id){
   chain* c;
   rule_tuple* r;
   chain** chain_list;
   if (fw_id <0){
      printf("Firewall ID out of range.\n");
      return 0;
   }
   if (chain_id <0 || chain_id > chain::numChains){
      printf("Chain out of range.\n");
      return 0;
   }
   chain_list = merged_chains[fw_id];
   if (chain_list == NULL){
      printf("Null Chain List encountered: Firewall %d, Chain %d.\n", fw_id, chain_id);
      return 0;
   }
   c = FindChain(fw_id, chain_id);
   if (c == NULL){
      printf("Null Chain Encountered: Firewall %d, Chain %d.\n", fw_id, chain_id);
      return 0;
   }
   if (rule_id == 0){
      printf("Firewall %d Chain %d Default.\n", fw_id, chain_id);
   }
   else{
      r = c->FindRule(rule_id);
      if (r == NULL){
         printf("Missing Rule.\n");
         return 0;
      }
      printf("Firewall %d Chain %d Rule %d: %s\n", fw_id, chain_id, rule_id, r->text);
   }
   return 1;
}

void Firewall::FindProblemClasses(mdd_handle conditionHistory){
   /*
    *   1.  Bring firewall_id, chain_id, and rule_id to top of conditionHistory MDD.
    *   2.  Generate classes over those three fields.
    *   3.  Print an element from each class.
    */
   printf("Not fully implemented.\n");
   printf("Input Chain: ");
   ProblemClassesInChain(InputHist, conditionHistory);
   printf("Forward Chain: ");
   ProblemClassesInChain(ForwardHist, conditionHistory);
   printf("Output Chain: ");
   ProblemClassesInChain(OutputHist, conditionHistory);
}

void Firewall::ProblemClassesInChain(mdd_handle ruleChain, mdd_handle conditionHistory){
   mdd_handle newMDD;
   int* problemClasses;
   int numClasses;
   int* tup;
   
   HistoryForest->Equals(conditionHistory, ruleChain, newMDD);
/*  
   HistoryForest->PruneMDD(newMDD);
   for (int k=25;k>0;k--)
      HistoryForest->Compact(k);
   HistoryForest->PrintMDD();
   assert(0);
*/
   
   HistoryForest->Shift(newMDD, 1, newMDD);	//Rule id
   HistoryForest->Shift(newMDD, 1, newMDD);	//Chain id
   HistoryForest->Shift(newMDD, 1, newMDD);	//Firewall id

   numClasses = HistoryForest->NumNodesAtLevel(TOP_LEVEL, newMDD); //Level below the three history rules.
   printf("%d classes:\n", numClasses);

   problemClasses = new int[numClasses];
   HistoryForest->GetNodesAtLevel(TOP_LEVEL, newMDD, problemClasses);
   for (int i=0;i<numClasses;i++){
      printf("  Class %d:\n\t", i);
      tup = new int[TOP_LEVEL+1];
      HistoryForest->FindInternalElement(TOP_LEVEL, problemClasses[i], T, tup);
      HistoryForest->PrintElement(T, tup);
      delete[] tup;
   }
   printf("\n");
   delete[] problemClasses;
}
