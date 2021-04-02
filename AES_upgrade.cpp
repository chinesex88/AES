#include <bits/stdc++.h>
using namespace std;
typedef unsigned char unit8_t;
//128bit input->32bit block(totla 4), each block divide to 4 subblock(8bit = 1 character)
#define Nb 4      //number of block (4 block, each block is 8 bit total is 128bit, Since AES fix input as 128bit, )
#define f_mx 0x1b //f_mx means input in function mx
//AES-128 system
unit8_t roundkey[240];
unit8_t state[4][4];
int keysize;
int Nb_k; //number of block of key since key might not 128bit
int Nr;   //Number of round
int Rcon[11] =
    {
        //0     1     2     3     4     5     6     7     8    9     10
        0x0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

uint8_t
GF256_add(uint8_t a, uint8_t b, uint8_t mx);
// returns a + b. mx is the irreducible polynomial

uint8_t GF256_mult_x(uint8_t a, uint8_t mx);
// Multiplied by x. mx is the irreducible polynomial

uint8_t GF256_mult(uint8_t a, uint8_t b, uint8_t mx);
// General multiplication: mx is the irreducible polynomial

uint8_t GF256_inv(uint8_t *a, uint8_t mx);
// Returns the multiplicative inverse of a. mx is the irreducible polynomial

void AES_Encrypt(uint8_t *Plaintext, uint8_t *Ciphertext, uint8_t *Key);
void AES_Decrypt(uint8_t *Plaintext, uint8_t *Ciphertext, uint8_t *Key);

unit8_t GF256_add(uint8_t a, unit8_t b, unit8_t mx)
{ //polynomail addition is same as binary xor
    return a ^ b;
}
unit8_t GF256_mult_x(unit8_t a, uint8_t mx)
{
    if (a & 0x80) //if a > 01111111
    {
        return (a << 1) ^ (mx); // mod mx same as XOR 1B
    }                           // a > 01111111
    return a << 1;
}
unit8_t GF256_mult(unit8_t a, unit8_t b, unit8_t mx)
{
    unit8_t ans = 0;
    unit8_t tmp;
    for (int i = 0; i < 8; i++)
    {
        tmp = a;
        if (b & 1) //if 7654321"0" = 1
        {
            for (int j = 0; j < i; j++)
            {
                tmp = GF256_mult_x(tmp, mx);
            }
            ans = GF256_add(ans, tmp, mx);
        }
        b >>= 1;
    }
    return ans;
}
uint8_t GF256_inv(uint8_t *a, uint8_t mx)
{ //since multi subgroup is cyclic with order 255, so input a^254 is a inverse
    unit8_t return_val = *a;
    //improve speed
    for (int i = 13; i != 0; i--)
    {
        return_val = GF256_mult(return_val, i & 1 ? return_val : *a, mx);
    }
    /*
    for (int i = 0; i < 253; i++)
    {
        counter++;
        return_val = GF256_mult(return_val, *a, f_mx);
    }
    */
    return return_val;
}
unit8_t leftshift1(unit8_t b)
{
    unit8_t h = b >> 7 & 1; //hightest bit
    b = b << 1;
    if (h)
        b ^= 0x1;
    return b;
}
unit8_t affine_transformation(unit8_t b)
{ //s=b+(b<<1)+(b<<2)+(b<<3)+(b<<4)+63_hex where << is circular shift, + is under GF256, b is multi inverse
    unit8_t s = 0x0;
    unit8_t tmp;
    for (int i = 0; i < 4; i++)
    {
        s = GF256_add(s, b, f_mx);
        b = leftshift1(b);
    }
    s = GF256_add(s, b, f_mx);
    s = GF256_add(s, 0x63, f_mx);
    return s;
}
unit8_t affine_transformation_inv(unit8_t s)
{ //b = s<<1 + s<<3 + s<<6 + 5_16
    unit8_t b = 0x0;
    unit8_t tmp;
    for (int i = 1; i <= 6; i++)
    {
        s = leftshift1(s);
        if (i == 1)
            b = GF256_add(b, s, f_mx);
        if (i == 3)
            b = GF256_add(b, s, f_mx);
        if (i == 6)
            b = GF256_add(b, s, f_mx);
    }
    b = GF256_add(b, 0x5, f_mx);
    return b;
}
void key_expasion(unit8_t *Key)
{
    unit8_t temp[4];
    unit8_t tmp;
    //first round subkey = main key divide to (Nb_k) block and each block is 32bit.
    //ex AES-128 4 block W0~W3
    for (int i = 0; i < Nb_k; i++)
    {
        roundkey[i * 4] = Key[i * 4];
        roundkey[i * 4 + 1] = Key[i * 4 + 1];
        roundkey[i * 4 + 2] = Key[i * 4 + 2];
        roundkey[i * 4 + 3] = Key[i * 4 + 3]; //i+0~i+4 is w_i(32bit)
    }
    //other subkey
    for (int i = Nb_k; i < (Nb * (Nr + 1)); i++)
    {
        for (int j = 0; j < Nb; j++)
            temp[j] = roundkey[(i - 1) * 4 + j]; //e.g. 計算w4需要先取w3的值做rotword subword xor rocn, w5 = w4 xor w1
        if (i % Nb_k == 0)
        {
            //Rotword
            tmp = temp[0];
            for (int c = 0; c < 3; c++)
                temp[c] = temp[c + 1];
            temp[3] = tmp;

            //subword(S-box substitution) means find inverse and do affine trans
            for (int c = 0; c < 4; c++)
            {
                temp[c] = affine_transformation(GF256_inv(&temp[c], f_mx));
            }

            //XOR (Rcon[i/Nb_k],0,0,0)
            temp[0] = GF256_add(temp[0], Rcon[i / Nb_k], f_mx);
        }
        else if (Nb_k == 8 && i % Nb_k == 4)
        {
            //AES-256
            //i mod 4 =0, i mod 8 !=0, W_n = Subword(W_(n-1)) XOR W_(n-8)
            for (int c = 0; c < 4; c++)
                temp[c] = affine_transformation(GF256_inv(&temp[c], f_mx));
        }
        // W_n = W_n-1 xor W_k, k = current word - Nb_k
        //eg: AES-128, Nb_k=4, W5 = W4 XOR W1
        for (int c = 0; c < 4; c++)
        {
            roundkey[i * 4 + c] = GF256_add(roundkey[(i - Nb_k) * 4 + c], temp[c], f_mx);
        }
    }
}
void AddRoundKey(int round)
{
    for (int i = 0; i < Nb; i++)
        for (int j = 0; j < Nb; j++)
            state[j][i] = GF256_add(state[j][i], roundkey[(i * Nb + j) + (round * Nb * 4)], f_mx);
    //0 round xor w0~w3 = roundkey[0]~roundkey[15]
    //1 round xor w1~w4
    // xor column by column
}
//S-BOX Substitution i.e. find inverse
void ByteSub()
{
    for (int i = 0; i < Nb; i++)
        for (int j = 0; j < Nb; j++)
            state[i][j] = affine_transformation(GF256_inv(&state[i][j], f_mx));
}

void ByteSub_inv()
{
    unit8_t tmp;
    for (int i = 0; i < Nb; i++)
        for (int j = 0; j < Nb; j++)
        {
            tmp = affine_transformation_inv(state[i][j]);
            state[i][j] = GF256_inv(&tmp, f_mx);
        }
}
void ShiftRow(char LorR)
{
    unit8_t tmp;
    if (LorR == 'L')
    {
        //1st row no shift
        //2nd row left shift by 1
        tmp = state[1][0];
        for (int c = 0; c < 3; c++)
            state[1][c] = state[1][c + 1];
        state[1][3] = tmp;
        //3rd row left shift by 2
        swap(state[2][0], state[2][2]);
        swap(state[2][1], state[2][3]);
        //4th row left shift by 3
        tmp = state[3][0];
        state[3][0] = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = tmp;
    }
    else if (LorR == 'R')
    {
        //1st row no shift
        //2nd row right shift by 1
        tmp = state[1][3];
        for (int i = 3; i > 0; i--)
            state[1][i] = state[1][i - 1];
        state[1][0] = tmp;
        //3rd row right shift by 2
        swap(state[2][0], state[2][2]);
        swap(state[2][1], state[2][3]);
        //4th row right shift by 3
        tmp = state[3][0];
        for (int i = 0; i < 3; i++)
            state[3][i] = state[3][i + 1];
        state[3][3] = tmp;
    }
}
void MixColumn()
{
    unit8_t temp[4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            temp[j] = state[j][i];
        }
        state[0][i] = (GF256_mult_x(temp[0], 0x1b)) ^ temp[3] ^ temp[2] ^ GF256_mult(temp[1], 3, 0x1b);
        state[1][i] = (GF256_mult_x(temp[1], 0x1b)) ^ temp[0] ^ temp[3] ^ GF256_mult(temp[2], 3, 0x1b);
        state[2][i] = (GF256_mult_x(temp[2], 0x1b)) ^ temp[1] ^ temp[0] ^ GF256_mult(temp[3], 3, 0x1b);
        state[3][i] = (GF256_mult_x(temp[3], 0x1b)) ^ temp[2] ^ temp[1] ^ GF256_mult(temp[0], 3, 0x1b);
    }
}
void MixColumn_inv()
{
    unit8_t temp[4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            temp[j] = state[j][i];
        }
        state[0][i] = (GF256_mult(temp[0], 14, 0x1b)) ^ (GF256_mult(temp[1], 11, 0x1b)) ^ (GF256_mult(temp[2], 13, 0x1b)) ^ GF256_mult(temp[3], 9, 0x1b);
        state[1][i] = (GF256_mult(temp[1], 14, 0x1b)) ^ (GF256_mult(temp[2], 11, 0x1b)) ^ (GF256_mult(temp[3], 13, 0x1b)) ^ GF256_mult(temp[0], 9, 0x1b);
        state[2][i] = (GF256_mult(temp[2], 14, 0x1b)) ^ (GF256_mult(temp[3], 11, 0x1b)) ^ (GF256_mult(temp[0], 13, 0x1b)) ^ GF256_mult(temp[1], 9, 0x1b);
        state[3][i] = (GF256_mult(temp[3], 14, 0x1b)) ^ (GF256_mult(temp[0], 11, 0x1b)) ^ (GF256_mult(temp[1], 13, 0x1b)) ^ GF256_mult(temp[2], 9, 0x1b);
    }
}
void AES_Encrypt(uint8_t *Plaintext, uint8_t *Ciphertext, uint8_t *Key)
{
    int round = 0;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[j][i] = Plaintext[i * 4 + j]; //conver plaintext to state matrix
    AddRoundKey(0);                             //round 0
    printf("Following is each round of Encrypt(Format is hex)\n");
    printf("Round 0 :\n");
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            printf("%x ", state[i][j]);
        }
        printf("\n");
    }
    for (round = 1; round < Nr; round++) //round 1 ~  Nr-1
    {

        ByteSub();
        ShiftRow('L');
        MixColumn();
        AddRoundKey(round);
        printf("Round %d\n", round);
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                printf("%x ", state[i][j]);
            }
            printf("\n");
        }
    }
    //final round
    ByteSub();
    ShiftRow('L');
    AddRoundKey(Nr);
    printf("Round %d\n", Nr);
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            printf("%x ", state[i][j]);
        }
        printf("\n");
    }
    //map state matrix to ciphertext
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Ciphertext[i * 4 + j] = state[j][i];
}
void AES_Decrypt(uint8_t *Plaintext, uint8_t *Ciphertext, uint8_t *Key)
{ //完全與加密相反，使用相同的subkey,只是也反過來使用，因此round沿用加密的round
    int round;

    //conver input ciphertext to state matrix
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            state[j][i] = Ciphertext[i * 4 + j];
    //round Nr
    AddRoundKey(Nr);
    printf("Following is each round of Decrypt(Format is hex)\n");
    printf("Round 0 :\n");
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            printf("%x ", state[i][j]);
        }
        printf("\n");
    }
    //round Nr-1~1
    for (round = Nr - 1; round > 0; round--)
    {
        ShiftRow('R');
        ByteSub_inv();
        AddRoundKey(round);
        MixColumn_inv();
        printf("Round %d\n", Nr - round);
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                printf("%x ", state[i][j]);
            }
            printf("\n");
        }
    }
    //round 0 no mixcolumn
    ShiftRow('R');
    ByteSub_inv();
    AddRoundKey(0);
    printf("Round %d\n", Nr);
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            printf("%x ", state[i][j]);
        }
        printf("\n");
    }
    //conver state to plaintext
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            Plaintext[i * 4 + j] = state[j][i];
}
int main()
{
    unit8_t key[16];
    unit8_t Plaintext[16];  //明文
    unit8_t Ciphertext[16]; //密文

    //IO,
    printf("input key size(need to be 128, 192, 256)\n");
    scanf("%d", &keysize);
    Nb_k = keysize / 32;
    Nr = Nb_k + 6;

    char tmp_in[20];
    printf("Enter AES Key (16 character for AES-128, 24 for 192, 32 for 256)\n");
    //READ BY CARACTER
    /*scanf("%s", tmp_in);
    for (int i = 0; i < keysize / 8; i++)
        key[i] = tmp_in[i];*/
    //READ BY HEX NUMBER
    int tmp;
    printf("input format is hex num\n");
    for (int i = 0; i < keysize / 8; i++)
    {
        scanf("%x", &tmp);
        key[i] = tmp;
    }

    key_expasion(key);
    printf("Enter Plaintext(Format is hex number)\n");
    //READ BY Character
    /*
    scanf("%s", tmp_in); //if less than 16 補零
    for (int i = 0; i < 16; i++)
    {
        Plaintext[i] = 0x0;
        if (i < strlen(tmp_in))
            Plaintext[i] = tmp_in[i];
    }
    */
    //READ BY HEX NUMBER
    for (int i = 0; i < 16; i++)
    {
        scanf("%x", &tmp);
        Plaintext[i] = tmp;
    }
    printf("\n");
    AES_Encrypt(Plaintext, Ciphertext, key);
    printf("First Plaintext input\n");
    for (int i = 0; i < 16; i++)
        printf("%x ", Plaintext[i]);
    printf("\n");
    printf("Final Cipher output :\n");
    for (int i = 0; i < 16; i++)
        printf("%x ", Ciphertext[i]);
    printf("\n");
    AES_Decrypt(Plaintext, Ciphertext, key);
    printf("Final Plaintext output :\n");
    for (int i = 0; i < 16; i++)
        printf("%x ", Plaintext[i]);
}