%pure-parser
%defines
%{
#include <string>
#include "src/parser.h"
#include "src/structures.h"
int yyerror(char* str);
%}

//%debug
%error-verbose

%union{
   int input_chain;
   char dummy;
   group* group_rec;
   service* service_rec;
   query* query_rec;
   assert* assert_rec;
   condition* condition_rec;
   int sub;
   int sv;
   int fv;
   int assert_op;
   port* port_rec;
   char *name;
   address* address_rec;
   int prot;
   char* val;
   int flag;
};

%{

YY_DECL;

%}

%token	 TOKEN_EOF   0	"end of file"

%left <group_rec> GROUP	      "group"
%left <service_rec> SERVICE   "service"
%left <query_rec> QUERY	      "query"
%left <assert_rec> ASSERT	"assert"

%token <input_chain> INPUT FORWARD OUTPUT "selected chain"
%token <flag> EXAMPLE HISTORY "ASSERTION flag"
%token <sub> PACKET SPORT DPORT SADDY DADDY STATE "query subject"
%token <query_rec> CLASSES "equivalence host classes"
%token <query_rec> SCLASSES "equivalence service classes"
%token <query_rec> SGRAPH "equivalence class graph"
%token <prot> UDP TCP ICMP BOTH	    "protocol"
%token <val> NUM		 "number"
%token <char> DOT		 "."
%token <assert_op> IS ISNT SUBSET_OF NOT_SUBSET_OF "assertion operators"
%token <condition_rec> LOGGED	    "logged condition"
%token <sv> T_INVALID T_NEW T_ESTABLISHED T_RELATED   "connection state"
%token <fv> FIN SYN RST PSH ACK URG		      "tcp flag"
%type <address_rec> addr			      "address"
%token <name> NAME				      "name"
%type <port_rec> port				      "port number"
%type <service_rec> compound_port		      "compound port"
%type <port_rec> complete_port			      "complete port"
%type <group_rec> compound_addy			      "compound address"
%type <condition_rec> simple_condition		      "simple condition"
%type <sv> state_value				      "state value"
%type <fv> flag_name				      "flag name"
%type <condition_rec> condition			      "query condition"
%type <sub> subject				      "subject keyword"
%type <input_chain> input_chain			      "input chain"
%type <prot> protocol				      "protocol keyword"
%type <assert_rec>assert_expression		      "assert expression"
%type <query_rec> query_expression		      "query expression"
%type <service_rec> service_expression		      "service declaration"
%type <group_rec> group_expression		      "address group declaration"
%type <address_rec> addy_list			      "address list"
%type <port_rec> port_list			      "port list"

%type <assert_op> assert_op			      "assertion operator"

%token <dummy> LPAREN RPAREN SEMI
%left <condition_rec> AND			      "AND"
%left <condition_rec> OR			      "OR"
%right <condition_rec> NOT			      "NOT"
%left <condition_rec> FROM TO FOR ON IN WITH INFACE OUTFACE ACCEPTED DROPPED"query primitive"

%%
statement: expression | expression statement;
expression: group_expression SEMI 
        | service_expression SEMI 
        | query_expression SEMI
	| assert_expression SEMI
        | SEMI
        ;
        
group_expression: GROUP NAME addy_list {$$ = DefineGroup($2, $3); delete[] $2;};

service_expression: SERVICE NAME port_list {$$ = DefineService($2, $3); delete[] $2;};

addy_list: addy_list addr {$$ = AppendAddy($1,$2);}
            | addr {$$ = AppendAddy(NULL, $1);};

port_list: port_list complete_port {$$ = AppendPort($1, $2);}
            | complete_port {$$ = AppendPort(NULL, $1);};

query_expression: QUERY CLASSES {$$ = PrintClasses(FLAG_NO_HISTORY);} 
          | QUERY SCLASSES {$$ = PrintServiceClasses(FLAG_NO_HISTORY);}
          | QUERY SGRAPH {$$ = PrintServiceGraph(FLAG_HISTORY);}
	  | QUERY HISTORY CLASSES {$$ = PrintClasses(FLAG_HISTORY);}
	  | QUERY HISTORY SCLASSES {$$ = PrintServiceClasses(FLAG_HISTORY);}
          | QUERY subject condition {$$ = PerformQuery($2, $3);}
//          | QUERY subject condition {$$ = PerformQuery($2, $3, 1);}
//          | QUERY subject input_chain condition {$$ = PerformQuery($2, $4, $3);} 
//          | QUERY input_chain subject condition {$$ = PerformQuery($3, $4, $2);}
;

assert_expression: ASSERT condition assert_op condition {$$ = PerformAssertion($2, $4, $3, FLAG_NO_EXAMPLE, FLAG_NO_HISTORY);}
	| ASSERT EXAMPLE condition assert_op condition {$$ = PerformAssertion($3, $5, $4, FLAG_EXAMPLE, FLAG_NO_HISTORY);}
	| ASSERT HISTORY condition assert_op condition {$$ = PerformAssertion($3, $5, $4, FLAG_NO_EXAMPLE, FLAG_HISTORY);}
	| ASSERT EXAMPLE HISTORY condition assert_op condition {$$ = PerformAssertion($4, $6, $5, FLAG_EXAMPLE, FLAG_HISTORY);}
	| ASSERT HISTORY EXAMPLE condition assert_op condition {$$ = PerformAssertion($4, $6, $5, FLAG_EXAMPLE, FLAG_HISTORY);}
		 ;

assert_op: IS {$$ = OP_IS;} 
	 | SUBSET_OF {$$= OP_SUBSET;}
	 | ISNT {$$ = OP_NOT_IS;}
	 | NOT_SUBSET_OF {$$ = OP_NOT_SUBSET;}
	 ;

input_chain: INPUT {$$ = 0;}
           | FORWARD {$$ = 1;}
           | OUTPUT {$$ = 2;}
			  ;

subject: PACKET{$$=0;} 
       | SPORT{$$=1;} 
       | DPORT{$$=2;} 
       | SADDY{$$=3;} 
       | DADDY{$$=4;} 
       | STATE{$$=5;}
       ;


condition: simple_condition {$$ = $1;}
        | condition AND condition {$$ = IntersectConditions($1,$3);}
        | condition OR condition {$$ = UnionConditions($1,$3);}
        | NOT condition {$$ = NegateCondition($2);}
        | LPAREN condition RPAREN {$$ = $2;}
        | LOGGED input_chain { $$ = GetLoggedCondition($2);}
        ;
        
simple_condition: FROM compound_addy {$$=BuildConditionFromGroup($2, 0);}
        | TO compound_addy {$$=BuildConditionFromGroup($2,1);}
        | ON compound_port {$$=BuildConditionFromService($2, 0);}
        | FOR compound_port {$$=BuildConditionFromService($2, 1);}
        | IN state_value {$$=BuildConditionFromState($2);}
        | WITH flag_name {$$=BuildConditionFromFlag($2);}
	| INFACE NAME {$$=BuildConditionFromIface($2, 0); delete[] $2;}
	| OUTFACE NAME {$$=BuildConditionFromIface($2, 1); delete[] $2;}
	| ACCEPTED input_chain {$$=BuildAcceptCondition($2);}
	| DROPPED input_chain {$$=BuildDropCondition($2);} 
	| ACCEPTED {$$=BuildAcceptCondition(1);}
	| DROPPED {$$=BuildDropCondition(1);} 
        ;

compound_addy: NAME {$$ = GroupLookup($1); delete[] $1;}
                | addr {$$ = BuildGroupFromAddress($1);};

compound_port: NAME {$$ = ServiceLookup($1); delete[] $1;}
                | complete_port {$$ = BuildServiceFromPort($1);};

state_value: T_INVALID{$$=0;} | T_NEW{$$=1;} | T_ESTABLISHED{$$=2;} | T_RELATED{$$=3;};

flag_name: FIN {$$=0;}| SYN {$$=1;}| RST {$$=2;}| PSH {$$=3;}| ACK{$$=4;} | URG {$$=5;};

complete_port: protocol port {$$ = BuildPort($1, $2);};

protocol: ICMP {$$ = 0;} | UDP {$$ = 1;} | TCP { $$ = 2;} | BOTH { $$ = -1;};

addr: NUM DOT NUM DOT NUM DOT NUM {$$ = ParseAddr($1,$3,$5,$7); delete[] $1; delete[] $3; delete[] $5; delete[] $7;} 
    | NUM DOT NUM DOT NUM {$$=ParseAddr($1,$3,$5,NULL); delete[] $1; delete[] $3; delete[] $5;} 
    | NUM DOT NUM{$$=ParseAddr($1,$3,NULL,NULL); delete[] $1; delete[] $3;} 
    | NUM {$$=ParseAddr($1,NULL,NULL,NULL); delete[] $1;};

port: NUM {$$=ParsePort($1); delete[] $1;};

%%

int yyerror(char* str){
   printf("%s\n", str);
}
