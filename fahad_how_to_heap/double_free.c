#include <stdio.h>
#include <stdlib.h>


typedef struct{

	char *name;
	int years;
}Expert;

Expert exp[50];

int add_expert(int idx){	

	int size;
	int input;
	printf("size:");
	scanf("%d",&size);
	exp[idx].name = malloc(size);
	printf("Name:");
	scanf("%s",exp[idx].name);
	printf("Experience:");
	scanf("%d",&exp[idx].years);
	// to count the experts 
	idx++;
	return idx;
}
void free_expert(){

	int index;
	printf("free_expert\n");
	printf("Index:");
	scanf("%d",&index);
	free(exp[index].name);

	printf("Sucessfully free : %d\n",index);
}
void show_expert(int idx){

	printf("--------------------------------\n");


	for (int i=0;i < idx; i++){
		printf("Expert:%s\n",exp[i].name);
		printf("years:%d\n",exp[i].years);
	}

	printf("--------------------------------\n");

}

void show_menu(){
	printf("------------------------------------------------\n");
	printf("#@0x4142\n");
	printf("------------------------------------------------\n");

	printf("1 - add_expert;\n2 - free_expert;\n3 - show_expert;\n4 - exit \n");
}

int main()

{

	/*  the purpose of this function is to add an expert*/
	int input;
	int num;
	int idx=0;
	int temp=0;
	do{
		if(temp > 0)idx=temp;

		show_menu();
		printf("Enter:");
		scanf("%d",&num);		
	switch(num){
		case 1:temp = add_expert(idx);continue;
		case 2:free_expert();break;
		case 3:show_expert(idx);break;
		case 4:printf("bye !\n");break;
		default:
			
			printf("try again sir !!\n");
			break;	
			}
	}while(num !=4);

	
		return 0;
	}





