#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int ROUNDS = 20;
unsigned long long bitshiftkey(unsigned long long, unsigned long long);
void encrypt(char*,char*,char*);
void decrypt(char*,char*,char*);
void whitening(char*,char*);
char** subkeyGeneration(char*,char*);
unsigned int fTable(int, int);
char* gfunction(char*, char*,char*,char*,char*);
unsigned int hexchartoint(char);
unsigned int gfunctionhelper(unsigned int, unsigned int, unsigned int);
void helpermethod(char*,char*);
/**
 * 7365637572697479, was the plaintext I was using for testing
 */
int main(int argc, char** argv){    
    if(argc < 2){
        printf("No arguments given\n");
    }else if(strlen(argv[1]) > 1){
        printf("%s is not a valid argument.\n",argv[1]);
        printf("use e for encrypt\n");
        printf("use d for decrypt\n");
    }else if(argv[1][0]=='e'){
        FILE* ptFile = fopen("./plaintext.txt","r");
        FILE* keyFile = fopen("./key.txt","r");
        FILE* cipherFile = fopen("./ciphertext.txt","w");
        if(ptFile == NULL||keyFile == NULL|| cipherFile == NULL){
            printf("An input file does not exist\n");
            exit(-1);
        }
        char* plaintext = (char*) calloc(17,sizeof(char));
        char* leftkey = (char*)calloc(5,sizeof(char));
        char* rightkey = (char*)calloc(17,sizeof(char));
        do{
            if(fgets(plaintext,17,ptFile) != NULL){
                while(strlen(plaintext)<16){
                    strcat(plaintext,"0");
                }   
                fgets(leftkey,5,keyFile);
                fgets(rightkey,17,keyFile);
                encrypt(plaintext,leftkey,rightkey);   
                printf("%s\n",plaintext);
                fprintf(cipherFile,"%s",plaintext);
            }
        }while(!feof(ptFile));
        free(plaintext);
        free(leftkey);
        free(rightkey);
        fclose(cipherFile);
        fclose(keyFile);
        fclose(ptFile);
    }else if(argv[1][0]=='d'){
        FILE* ptFile = fopen("./plaintext.txt","w");
        FILE* keyFile = fopen("./key.txt","r");
        FILE* cipherFile = fopen("./ciphertext.txt","r");
        if(ptFile == NULL||keyFile == NULL|| cipherFile == NULL){
            printf("An input file does not exist\n");
            exit(-1);
        }
        char* ciphertext = (char*) calloc(17,sizeof(char));
        char* leftkey = (char*)calloc(5,sizeof(char));
        char* rightkey = (char*)calloc(17,sizeof(char));        
        do{
            if(fgets(ciphertext,17,cipherFile) != NULL){
                while(strlen(ciphertext)<16){
                    strcat(ciphertext,"0");
                }   
                fgets(leftkey,5,keyFile);
                fgets(rightkey,17,keyFile);
                decrypt(ciphertext,leftkey,rightkey);
                printf("%s\n",ciphertext);
                fprintf(ptFile,"%s",ciphertext);
            }
        }while(!feof(cipherFile));
        free(ciphertext);
        free(leftkey);
        free(rightkey);
        fclose(cipherFile);
        fclose(keyFile);
        fclose(ptFile);
    }else{
        printf("%c is not a valid argument.\n",argv[1][0]);
        printf("use e for encrypt\n");
        printf("use d for decrypt\n");
    }
    return 0;
}
/**
*   Takes the plain text and encrypts the text using the keys
*
*   This menthod drives the encryption proccess making sure that
*   the encryption proccess. Creates the subkeys whitens the plaintext
*   make sure that the text goes through 20 rounds of the fistel cipher.
*   
*   @param char* plaintext: the text you are looking to encrypt, hex values
*   @param char* keyleft: the left 16 bits of the 80 bit key. 
*   @param char* keyright: the right 64 bits of the 80 bit key.
*/
void encrypt(char* plaintext, char* keyleft, char* keyright){
    whitening(plaintext,keyright);
    char** subkeys = subkeyGeneration(keyleft,keyright);

    //the start of the  encryption proccess
    for(int i=0;i<ROUNDS;i++){
        char* subkeyset = subkeys[i];
        helpermethod(plaintext,subkeyset);
    }
    whitening(plaintext,keyright);
    for(int i=0;i < ROUNDS;i++){
        free(subkeys[i]);
    }
    free(subkeys);   
}

/**
 *  Takes the cipher text and decripts the string back to the original text.  
 * 
 *  does the same thing as the encrypt method. However instead of going from 0-19, this 
 *  goes from 19-0.
 * 
 *  @param char*ciphertext: the text you are looking to decrypt, hex values
 *  @param char* keyleft: the left 16 bits of the 80 bit key. 
 *  @param char* keyright: the right 64 bits of the 80 bit key.
 */
void decrypt(char* ciphertext, char* keyleft, char* keyright){
    whitening(ciphertext,keyright);
    char** subkeys = subkeyGeneration(keyleft,keyright);

    //the start of the  encryption proccess
    for(int i=ROUNDS-1;i>=0;i-=1){
        char* subkeyset = subkeys[i];
        helpermethod(ciphertext,subkeyset);
    }
    whitening(ciphertext,keyright);
    
    for(int i=0;i < ROUNDS;i++){
        free(subkeys[i]);
    }
    free(subkeys); 
}

/**
 *  This is the method that does text manipulation. 
 * 
 *  This method drives the festel cipher part of the encryption. it take the text
 *  plits into four parts and moves the left to the right, and xors the right from
 *  what is generated from the function.
 * 
 * @param char* plaintext: this is the text that you are gonna be modifying 
 * @param char* subkeyset: this is the set of 12 keys that changes depending on the round # 
 */
void helpermethod(char* plaintext, char* subkeyset){
    char r0[5];
    r0[0] = plaintext[0];
    r0[1] = plaintext[1];
    r0[2] = plaintext[2];
    r0[3] = plaintext[3];
    r0[4] = '\0';
    while(strlen(r0) < 4){
        char temp1 = r0[0];
        char temp2 = r0[1];
        r0[0] = '0';
        r0[1] = temp1;
        temp1 = r0[2];
        r0[2] = temp2;
        temp2 = r0[3];
        r0[3] = temp1;
        r0[4] = '\0';
    }
    char r1[5];
    r1[0] = plaintext[4];
    r1[1] = plaintext[5];
    r1[2] = plaintext[6];
    r1[3] = plaintext[7];
    r1[4] = '\0';
    while(strlen(r1) < 4){
        char temp3 = r1[0];
        char temp4 = r1[1];
        r1[0] = '0';
        r1[1] = temp3;
        temp3 = r1[2];
        r1[2] = temp4;
        temp4 = r1[3];
        r1[3] = temp3;
        r1[4] = '\0';
    }
    char r2[5];
    r2[0] = plaintext[8];
    r2[1] = plaintext[9];
    r2[2] = plaintext[10];
    r2[3] = plaintext[11];
    r2[4] = '\0';
    while(strlen(r2) < 4){
        char temp5 = r2[0];
        char temp6 = r2[1];
        r2[0] = '0';
        r2[1] = temp5;
        temp5 = r2[2];
        r2[2] = temp6;
        temp5 = r2[3];
        r2[3] = temp5;
        r2[4] = '\0';
    }
    char r3[5];
    r3[0] = plaintext[12];
    r3[1] = plaintext[13];
    r3[2] = plaintext[14];
    r3[3] = plaintext[15];
    r3[4] = '\0';
    while(strlen(r3) < 4){
        char temp7 = r3[0];
        char temp8 = r3[1];
        r3[0] = '0';
        r3[1] = temp7;
        temp7 = r3[2];
        r3[2] = temp8;
        temp8 = r3[3];
        r3[3] = temp7;
        r3[4] = '\0';
    }

    char k0[3];
    k0[0] = subkeyset[0];
    k0[1] = subkeyset[1];
    k0[2] = '\0'; 
    while(strlen(k0)<2){
        char keytemp = k0[0];
        k0[0] = '0';
        k0[1] = keytemp;
    }
    char k1[3];
    k1[0] = subkeyset[2];
    k1[1] = subkeyset[3];
    k1[2] = '\0'; 
    while(strlen(k1)<2){
        char keytemp1 = k1[0];
        k1[0] = '0';
        k1[1] = keytemp1;
    }
    char k2[3];
    k2[0] = subkeyset[4];
    k2[1] = subkeyset[5];
    k2[2] = '\0'; 
    while(strlen(k2)<2){
        char keytemp2 = k2[0];
        k2[0] = '0';
        k2[1] = keytemp2;
    }
    char k3[3];
    k3[0] = subkeyset[6];
    k3[1] = subkeyset[7];
    k3[2] = '\0'; 
    while(strlen(k3)<2){
        char keytemp1 = k3[0];
        k3[0] = '0';
        k3[1] = keytemp1;
    }
    char k4[3];
    k4[0] = subkeyset[8];
    k4[1] = subkeyset[9];
    k4[2] = '\0';
    while(strlen(k1)<2){
        char keytemp1 = k1[0];
        k1[0] = '0';
        k1[1] = keytemp1;
    }
    char k5[3];
    k5[0] = subkeyset[10];
    k5[1] = subkeyset[11];
    k5[2] = '\0'; 
    while(strlen(k5)<2){
        char keytemp1 = k5[0];
        k5[0] = '0';
        k5[1] = keytemp1;
    }
    char k6[3];
    k6[0] = subkeyset[12];
    k6[1] = subkeyset[13];
    k6[2] = '\0'; 
    while(strlen(k6)<2){
        char keytemp2 = k6[0];
        k6[0] = '0';
        k6[1] = keytemp2;
    }
    char k7[3];
    k7[0] = subkeyset[14];
    k7[1] = subkeyset[15];
    k7[2] = '\0'; 
    while(strlen(k7)<2){
        char keytemp1 = k7[0];
        k7[0] = '0';
        k7[1] = keytemp1;
    }
    char k8[3];
    k8[0] = subkeyset[16];
    k8[1] = subkeyset[17];
    k8[2] = '\0'; 
    while(strlen(k8)<2){
        char keytemp2 = k8[0];
        k8[0] = '0';
        k8[1] = keytemp2;
    }
    char k9[3];
    k9[0] = subkeyset[18];
    k9[1] = subkeyset[19];
    k9[2] = '\0'; 
    while(strlen(k9)<2){
        char keytemp1 = k9[0];
        k9[0] = '0';
        k9[1] = keytemp1;
    }
    char k10[3];
    k10[0] = subkeyset[20];
    k10[1] = subkeyset[21];
    k10[2] = '\0'; 
    while(strlen(k10)<2){
        char keytemp2 = k10[0];
        k10[0] = '0';
        k10[1] = keytemp2;
    }
    char k11[3];
    k11[0] = subkeyset[22];
    k11[1] = subkeyset[23];
    k11[2] = '\0'; 
    while(strlen(k11)<2){
        char keytemp1 = k11[0];
        k11[0] = '0';
        k11[1] = keytemp1;
    }
    
    unsigned long long r0Value = strtoull(r0,NULL,16);
    unsigned long long r1Value = strtoull(r1,NULL,16);
    unsigned long long r2Value = strtoull(r2,NULL,16);
    unsigned long long r3Value = strtoull(r3,NULL,16);

    //printf("%s\n",subkeyset);
    char* T0 = gfunction(r0,k0,k1,k2,k3);
    char* T1 = gfunction(r1,k4,k5,k6,k7);
    //printf("T0:%s T1:%s\n",T0,T1);
    char temp[5];
    sprintf(temp,"%s%s",k8,k9);
    while(strlen(temp) < 4){
        char temp1 = temp[0];
        char temp2 = temp[1];
        temp[0] = '0';
        temp[1] = temp1;
        temp1 = temp[2];
        temp[2] = temp2;
        temp2 = temp[3];
        temp[3] = temp1;
        temp[4] = '\0';
    }
    unsigned long long k8k9Value = strtoull(temp,NULL,16);

    sprintf(temp,"%s%s",k10,k11);
    while(strlen(temp) < 4){
        char temp1 = temp[0];
        char temp2 = temp[1];
        temp[0] = '0';
        temp[1] = temp1;
        temp1 = temp[2];
        temp[2] = temp2;
        temp2 = temp[3];
        temp[3] = temp1;
        temp[4] = '\0';
    }
    unsigned long long k10k11Value = strtoull(temp,NULL,16);
    unsigned long long T0Value = strtoull(T0,NULL,16);
    unsigned long long T1Value = strtoull(T1,NULL,16);
    unsigned long long exponet = (unsigned long long)(pow(2,16));
    unsigned long long F0Value = (T0Value+(2*T1Value)+k8k9Value)%exponet;
    unsigned long long F1Value = ((2*T0Value)+T1Value+k10k11Value) % exponet;
    //printf("T0:%s %lli T1:%s %lli\n",T0,T0Value,T1,T1Value);
    //printf("F0: %lli %lli %lli %lli\nF1: %lli %lli %lli %lli\n",T0Value,2*T1Value,k8k9Value,F0Value,2*T0Value,T1Value,k10k11Value,F1Value);
    //printf("F0:%llx F1:%llx\n",F0Value,F1Value);
    //printf("R0:%llx R1:%llx R2:%llx R3:%llx\n",r0Value,r1Value,r2Value,r3Value);
    unsigned long long newR0Value = F0Value ^ r2Value;
    unsigned long long newR1Value = F1Value ^ r3Value;
    //printf("newR0:%llx newR1:%llx\n",newR0Value,newR1Value);

    char newR1[5];
    sprintf(newR1,"%llx",newR1Value);
    while(strlen(newR1)<4){
        char temp1 = newR1[0];
        char temp2 = newR1[1];
        newR1[0] = '0';
        newR1[1] = temp1;
        temp1 = newR1[2];
        newR1[2] = temp2;
        temp2 = newR1[3];
        newR1[3] = temp1;
        newR1[4] = '\0';    
    }

    char newLeft[9];
    sprintf(newLeft,"%llx%s",newR0Value,newR1);
    while(strlen(newLeft)<8){
        char temp1 = newLeft[0];
        char temp2 = newLeft[1];
        newLeft[0] = '0';       
        newLeft[1] = temp1;
        temp1 = newLeft[2];
        newLeft[2] = temp2;
        temp2 = newLeft[3];
        newLeft[3] = temp1;
        temp1 = newLeft[4];
        newLeft[4] = temp2;
        temp2 = newLeft[5];
        newLeft[5] = temp1;
        temp1 = newLeft[6];
        newLeft[6] = temp2;
        temp2 = newLeft[7];
        newLeft[7] = temp1;
    }
    char newRight[9];
    sprintf(newRight,"%s%s",r0,r1);
    while(strlen(newLeft)<8){
        char temp1 = newRight[0];
        char temp2 = newRight[1];
        newRight[0] = '0';       
        newRight[1] = temp1;
        temp1 = newRight[2];
        newRight[2] = temp2;
        temp2 = newRight[3];
        newRight[3] = temp1;
        temp1 = newRight[4];
        newRight[4] = temp2;
        temp2 = newRight[5];
        newRight[5] = temp1;
        temp1 = newRight[6];
        newRight[6] = temp2;
        temp2 = newRight[7];
        newRight[7] = temp1;
    }
    //printf("%s%s\n",newLeft,newRight);

    sprintf(plaintext,"%s%s",newLeft,newRight);
    free(T0);
    free(T1);
}


/**
 *  This method xor's the text with the key
 *  
 *  @param char* plaintext: the text you are manipulating.
 *  @param char* keyright: the key that you are using in the xor
 */ 
void whitening(char* plaintext, char* keyright){
    unsigned long long ptValue = strtoull(plaintext,NULL,16);
    unsigned long long krValue = strtoull(keyright,NULL,16);
    unsigned long long xor = ptValue ^ krValue;
    sprintf(plaintext,"%llx",xor);
}

/**
 *  Generates the subkeys that are used in the gFunction
 * 
 *  Every time a subkey is to be generated you have to shift the bits by one.
 *  Because the key is a 80bit key the key has to be stored in two seperate values. I chose 
 *  to store the key in a unsigned short and a unsigned long long. 
 * 
 *  @param char* leftkey: the left 16 bits of the key
 *  @param char* rightkey: the right 64 bits of the key 
 * 
 *  @return char** subkeyset: is the collection of the subkey sets for all the rounds, 
 *      in this case all 20 rounds.
 */
char** subkeyGeneration(char* leftkey, char* rightkey){
    char** subkeys = (char**)calloc(ROUNDS,sizeof(char*));
    for(int i=0;i<ROUNDS;i++)
        subkeys[i] = (char*)calloc(25,sizeof(char*));
    unsigned short lkValue = (unsigned short) strtoul(leftkey,NULL,16);
    unsigned long long rkValue = strtoull(rightkey,NULL,16);
    for(int rounds = 0; rounds < ROUNDS;rounds++){
        int index =0;
        for(int i = 0; i < 12; i++){
            unsigned short lkValueShift = lkValue << 1;
            unsigned short lkValueShiftRemainder = lkValue >> 15;

            unsigned long long rkValueShift = rkValue << 1;
            unsigned long long rkValueShiftRemainder = rkValue >> 63;

            lkValue = lkValueShift | rkValueShiftRemainder;
            rkValue = rkValueShift | lkValueShiftRemainder;

            char left[5];
            sprintf(left,"%hx",lkValue);
            while(strlen(left) < 4){
                char temp1 = left[0];
                char temp2 = left[1];
                left[0] = '0';
                left[1] = temp1;
                temp1 = left[2];
                left[2] = temp2;
                temp2 = left[3];
                left[3] = temp1;
                left[4] = temp2;
            }            
            char right[17];
            sprintf(right,"%llx",rkValue);
            while(strlen(right)<16){
                char temp1 = right[0];
                char temp2 = right[1];
                right[0] = '0';
                
                right[1] = temp1;
                temp1 = right[2];
                right[2] = temp2;
                temp2 = right[3];
                right[3] = temp1;
                temp1 = right[4];
                right[4] = temp2;
                temp2 = right[5];
                right[5] = temp1;
                temp1 = right[6];
                right[6] = temp2;
                temp2 = right[7];
                right[7] = temp1;
                temp1 = right[8];
                right[8] = temp2;
                temp2 = right[9];
                right[9] = temp1;
                temp1 = right[10];
                right[10] = temp2;
                temp2 = right[11];
                right[11] = temp1;
                temp1 = right[12];
                right[12] = temp2;
                temp2 = right[13];
                right[13] = temp2;
                temp2 = right[14];
                right[14] = temp1;
                temp1 = right[15];
                right[15] = temp2;
                temp2 = right[16];
                right[16] = temp1;        
            }

            char key[3];
            int roundNum = (4*rounds+index)%8;
            index += 1;
            index = index % 4;

            int rightLen = strlen(right);
            key[1] = right[(rightLen-1)-(2*roundNum)];
            key[0] = right[rightLen-(2*(roundNum+1))];
            key[2] = '\0';

            strcat(subkeys[rounds],key);
            printf("%s%s subkey: %s\n",left,right,key);
        }
        printf("subkeys:%s\n\n",subkeys[rounds]);
    }

    return subkeys;
}
/**
 *  Generates g0-g6, which g5 g6 are put together and returned fpr the T values.
 * 
 *  @param char* section: the 2 byte section of code that is used to generate g1,g2
 *  @param char* k0,k1,k2,k3: are the 4 subkeys that are used.
 * 
 *  @return char* the T value that is g5and g6 put together is returned.
 */
char* gfunction(char* section, char* k0, char* k1, char* k2, char* k3){
    char g1[3];
    g1[0] = section[0];
    g1[1] = section[1];
    g1[2] = '\0'; 
    while(strlen(g1)<2){
        char temp = g1[0];
        g1[0] = '0';
        g1[1] = temp;
    }
    char g2[3];
    g2[0] = section[2];
    g2[1] = section[3];
    g2[2] = '\0'; 
    while(strlen(g2)<2){
        char temp = g2[0];
        g2[0] = '0';
        g2[1] = temp;
    }

    unsigned int k0Value = strtoul(k0,NULL,16);
    unsigned int k1Value = strtoul(k1,NULL,16);
    unsigned int k2Value = strtoul(k2,NULL,16);
    unsigned int k3Value = strtoul(k3,NULL,16);

    unsigned int g1Value = strtoul(g1,NULL,16);
    unsigned int g2Value = strtoul(g2,NULL,16);
    unsigned int g3Value = gfunctionhelper(g1Value,g2Value,k0Value);
    unsigned int g4Value = gfunctionhelper(g2Value,g3Value,k1Value);
    unsigned int g5Value = gfunctionhelper(g3Value,g4Value,k2Value);
    unsigned int g6Value = gfunctionhelper(g4Value,g5Value,k3Value);

    char g5[3];
    sprintf(g5,"%x",g5Value);
    while(strlen(g5)<2){
        char temp = g5[0];
        g5[0] = '0';
        g5[1] = temp;
    }
    g5[2] = '\0';

    char g6[3];
    sprintf(g6,"%x",g6Value);
    while(strlen(g6)<2){
        char temp = g6[0];
        g6[0] = '0';
        g6[1] = temp;
    }
    g6[2] = '\0';

    char* TValue = (char*)calloc(5,sizeof(char));
    sprintf(TValue,"%s%s",g5,g6);
    //sprintf(TValue,"%x%x",g5Value,g6Value);
    //printf("g1:%x g2:%x g3:%x g4:%x g5:%x g6:%x\n",g1Value,g2Value,g3Value,g4Value,g5Value,g6Value);
    return TValue;
}
/**
 *  This method generates the new G values
 * 
 *  This method xor's one of the g values with key values and asks the ftable for a values based
 *  on that value. That values is then xor'd with the second g value. The value that is gernated from 
 *  that xor is returned as a new g value.
 * 
 *  @param int g1Value: is xor'd with the value returned from the ftable
 *  @param int g2Value is xord'd with key to get location in ftable
 *  @param int keyValue is xor'd with g2Value to get location in ftable
 * 
 *  @return unsigned int: the value of the new gValue.
 */
unsigned int gfunctionhelper(unsigned int g1Value,unsigned int g2Value,unsigned int keyValue){
    unsigned int input = g2Value ^ keyValue;
    char ftb[3];
    sprintf(ftb,"%x",input);
    while(strlen(ftb)<2){
        char temp = ftb[0];
        ftb[0] = '0';
        ftb[1] = temp;
    }
    unsigned int ftbValue = fTable(hexchartoint(ftb[0]),hexchartoint(ftb[1]));
    //printf("gValue:%x keyValue:%x input:%x FTableValue:%x gValue:%x\n",g2Value,keyValue,input, ftbValue, g1Value);
    unsigned int newgValue = ftbValue ^ g1Value;
    return newgValue; 
}

/**
 *  returns the int value of hex based value that was passed (based on char passed)
 * 
 *  @param char letter: a character that represents a hex value from 0-f
 *  
 *  @return unsigned int: returns the decimal value of the hex value passed. returns -1 if not a hex value.
 */
unsigned int hexchartoint(char letter){
    if(letter == '0') return 0;
    if(letter == '1') return 1;
    if(letter == '2') return 2;
    if(letter == '3') return 3;
    if(letter == '4') return 4;
    if(letter == '5') return 5;
    if(letter == '6') return 6;
    if(letter == '7') return 7;
    if(letter == '8') return 8;
    if(letter == '9') return 9;
    if(letter == 'a') return 10;
    if(letter == 'b') return 11;
    if(letter == 'c') return 12;
    if(letter == 'd') return 13;
    if(letter == 'e') return 14;
    if(letter == 'f') return 15;
    return -1;
}

/**
 *  returns the value stored in the table based on the index that are pased.
 *  
 *  @param int x: the row index for the table
 *  @param int y: the collum index for the table
 * 
 *  @return unsigned int: returns the hex value of the information stored at x,y. 
 */
unsigned int fTable(int x, int y){
    char FTable[16][16][3] = {
        //0     1    2    3    4    5    6    7    8    9    a    b    c    d    e    f
        {"a3","d7","09","83","f8","48","f6","f4","b3","21","15","78","99","b1","af","f9"},//0
        {"e7","2d","4d","8a","ce","4c","ca","2e","52","95","d9","1e","4e","38","44","28"},//1
        {"0a","df","02","a0","17","f1","60","68","12","b7","7a","c3","e9","fa","3d","53"},//2
        {"96","84","6b","ba","f2","63","9a","19","7c","ae","e5","f5","f7","16","6a","a2"},//3
        {"39","b6","7b","0f","c1","93","81","1b","ee","b4","1a","ea","d0","91","2f","b8"},//4
        {"55","b9","da","85","3f","41","bf","e0","5a","58","80","5f","66","0b","d8","90"},//5
        {"35","d5","c0","a7","33","06","65","69","45","00","94","56","6d","98","9b","76"},//6
        {"97","fc","b2","c2","b0","fe","db","20","e1","eb","d6","e4","dd","47","4a","1d"},//7
        {"42","ed","9e","6e","49","3c","cd","43","27","d2","07","d4","de","c7","67","18"},//8
        {"89","cb","30","1f","8d","c6","8f","aa","c8","74","dc","c9","5d","5c","31","a4"},//9
        {"70","88","61","2c","9f","0d","2b","87","50","82","54","64","26","7d","03","40"},//a
        {"34","4b","1c","73","d1","c4","fd","3b","cc","fb","7f","ab","e6","3e","5b","a5"},//b
        {"ad","04","23","9c","14","51","22","f0","29","79","71","7e","ff","8c","0e","e2"},//c
        {"0c","ef","bc","72","75","6f","37","a1","ec","d3","8e","62","8b","86","10","e8"},//d
        {"08","77","11","be","92","4f","24","c5","32","36","9d","cf","f3","a6","bb","ac"},//e
        {"5e","6c","a9","13","57","25","b5","e3","bd","a8","3a","01","05","59","2a","46"}//f
    };
    return strtoul(FTable[x][y],NULL,16);
}