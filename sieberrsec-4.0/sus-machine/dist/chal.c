#include<stdio.h>
#include <string.h>


void setup(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

char crewmates[5][10] = {"red","blue","pink","orange","purple"};


char menu[] = "Menu:\n1. Kill Crewmate\n2. Leave game\n> ";

char input[50] = "Dummy input";

char name[] = "Impostor";


int vuln(){
    char choice;
    char crewmateName[20];

    while(1){
        printf(menu);
        choice = getchar();
        getchar();
        if(choice == '1'){
            printf("Enter crewmate name: ");
            fgets(crewmateName, 19, stdin);
            strncat(input, crewmateName, 20);
            for(int i =0;i<5;i++){
                if(strstr(input, crewmates[i]) != NULL){
                    puts("\n\n"
                        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⢀⣔⣷⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡝⠉⠉⠽⣿⣃⣼⣷⠶⣦⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠫⢿⣄⠀⠀⠈⣿⠁⠀⠀⣁⣟⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⢛⣷⢂⠀⠀⠀⣀⡷⢣⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⣿⡾⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⣿⠀⠀⠀⣿⠇⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢚⣾⠀⠀⠀⣽⡀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⣿⠀⠀⠀⣿⡍⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
                        "⠀⣸⣿⡏⠉⣙⣿⣿⣷⣶⣖⣷⣶⣿⣿⡲⣶⣲⣿⢗⣶⣖⣶⣲⣾⣛⢗⣷⠀⠀⠀\n"
                        "⠀⣿⣿⠁⠀⠉⣿⣿⡟⠛⠟⠝⠏⢙⠉⠙⠉⠋⠍⠙⠙⠉⠛⠛⠛⣻⣿⣿⠀⠀⠀\n"
                        "⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀\n"
                        "⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀⠀\n"
                        "⠀⢿⣿⡆⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀⠀\n"
                        "⠀⠸⣿⣧⡀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀⠀\n"
                        "⠀⠀⠛⢿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⣰⣿⣿⣷⣶⣶⣶⣶⠶⠀⢠⣿⣿⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⣽⣿⡏⠁⠀⠀⢸⣿⡇⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⢹⣿⡆⠀⠀⠀⣸⣿⠇⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⢿⣿⣦⣄⣀⣠⣴⣿⣿⠁⠀⠈⠻⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀⠀\n"
                        "⠀⠀⠀⠀⠀⠀⠀⠈⠛⠻⠿⠿⠿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n\n");
                    printf("%s was killed by ", crewmates[i]);
                    printf(name);
                    printf(".\n\n");
                    *input = '\0';
                    break;
                }
            }
        }else if(choice == '2'){
            break;
        }
    }
}



int main(){
	setup();
    puts(
"    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣤⣤⣤⣶⣦⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀");
puts(
"⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠛⠉⠙⠛⠛⠛⠛⠻⢿⣿⣷⣤⡀⠀⠀⠀⠀⠀");
puts(
"⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⠋⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠈⢻⣿⣿⡄⠀⠀⠀⠀");
puts(
"⠀⠀⠀⠀⠀⠀⠀⣸⣿⡏⠀⠀⠀⣠⣶⣾⣿⣿⣿⠿⠿⠿⢿⣿⣿⣿⣄⠀⠀⠀");
puts(
"⠀⠀⠀⠀⠀⠀⠀⣿⣿⠁⠀⠀⢰⣿⣿⣯⠁⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣷⡄⠀");
puts(
"⠀⠀⣀⣤⣴⣶⣶⣿⡟⠀⠀⠀⢸⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣷⠀");
puts(
"⠀⢰⣿⡟⠋⠉⣹⣿⡇⠀⠀⠀⠘⣿⣿⣿⣿⣷⣦⣤⣤⣤⣶⣶⣶⣶⣿⣿⣿⠀\n"
"⠀⢸⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀\n"
"⠀⣸⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠉⠻⠿⣿⣿⣿⣿⡿⠿⠿⠛⢻⣿⡇⠀⠀\n"
"⠀⣿⣿⠁⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣧⠀⠀\n"
"⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀\n"
"⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀\n"
"⠀⢿⣿⡆⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀\n"
"⠀⠸⣿⣧⡀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀\n"
"⠀⠀⠛⢿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⣰⣿⣿⣷⣶⣶⣶⣶⠶⠀⢠⣿⣿⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⣽⣿⡏⠁⠀⠀⢸⣿⡇⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⢹⣿⡆⠀⠀⠀⣸⣿⠇⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⢿⣿⣦⣄⣀⣠⣴⣿⣿⠁⠀⠈⠻⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀\n"
"⠀⠀⠀⠀⠀⠀⠀⠈⠛⠻⠿⠿⠿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n\n");
    vuln();
}

void vent(){
    execve("/bin/sh",NULL,NULL);
}