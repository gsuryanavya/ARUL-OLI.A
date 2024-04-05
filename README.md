# ARUL-OLI.A
Cryptography and Network Security
# CAESAR CIPHER
```
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main() {
    char plain[10], cipher[10];
    int key, i, length;
    printf("\n Enter the plain text: ");
    scanf("%s", plain);
    printf("\n Enter the key value: ");
    scanf("%d", &key);

    printf("\n \n \t PLAIN TEXT: %s", plain);
    printf("\n \n \t ENCRYPTED TEXT: ");
    
    length = strlen(plain); // Calculate length outside the loop

    for (i = 0; i < length; i++) {
        cipher[i] = plain[i] + key;
        if (isupper(plain[i]) && (cipher[i] > 'Z'))
            cipher[i] = cipher[i] - 26;
        if (islower(plain[i]) && (cipher[i] > 'z'))
            cipher[i] = cipher[i] - 26;
        printf("%c", cipher[i]);
    }

    printf("\n \n \t AFTER DECRYPTION : ");
    for (i = 0; i < length; i++) {
        plain[i] = cipher[i] - key;
        if (isupper(cipher[i]) && (plain[i] < 'A'))
            plain[i] = plain[i] + 26;
        if (islower(cipher[i]) && (plain[i] < 'a'))
            plain[i] = plain[i] + 26;
        printf("%c", plain[i]);
    }
    printf("\n");
    return 0;
}
```
# OUTPUT

![Screenshot 2024-04-05 191153](https://github.com/gsuryanavya/ARUL-OLI.A/assets/133086963/1d91861b-c4b0-455b-a3a3-5484e4b0534d)


# HILL CIPHER
```
#include<stdio.h>
#include<string.h>

int main() {
    unsigned int a[3][3] = {{6,24,1}, {13,16,10}, {20,17,15}};
    unsigned int b[3][3] = {{8,5,10}, {21,8,21}, {21,12,8}};
    int i, j, t = 0;
    unsigned int c[20], d[20];
    char msg[20];
    
    printf("Enter plain text: ");
    scanf("%s", msg);
    
    for(i = 0; i < strlen(msg); i++) {
        c[i] = msg[i] - 65;
        printf("%d ", c[i]);
    }
    
    for(i = 0; i < 3; i++) {
        t = 0;
        for(j = 0; j < 3; j++) {
            t += a[i][j] * c[j];
        }
        d[i] = t % 26;
    }
    
    printf("\nEncrypted Cipher Text:");
    for(i = 0; i < 3; i++)
        printf(" %c", d[i] + 65);
    
    for(i = 0; i < 3; i++) {
        t = 0;
        for(j = 0; j < 3; j++) {
            t += b[i][j] * d[j];
        }
        c[i] = t % 26;
    }
    
    printf("\nDecrypted Cipher Text:");
    for(i = 0; i < 3; i++)
        printf(" %c", c[i] + 65);
    
    return 0;
}
```
# OUTPUT
![Screenshot 2024-04-05 191000](https://github.com/gsuryanavya/ARUL-OLI.A/assets/133086963/a1e29e6f-732e-4932-8e79-5fa03ef5b8ec)

# VIGENERE CIPHER
```
#include <stdio.h>
#include <ctype.h>
#include <string.h>

void encipher();
void decipher();

int main() {
    int choice;

    while (1) {
        printf("\n1. Encrypt Text");
        printf("\t2. Decrypt Text");
        printf("\t3. Exit");
        printf("\n\nEnter Your Choice : ");
        scanf("%d", &choice);

        if (choice == 3)
            return 0;
        else if (choice == 1)
            encipher();
        else if (choice == 2)
            decipher();
        else
            printf("Please Enter Valid Option.");
    }
    return 0;
}

void encipher() {
    unsigned int i, j;
    char input[50], key[10];

    printf("\n\nEnter Plain Text: ");
    scanf("%s", input);

    printf("\nEnter Key Value: ");
    scanf("%s", key);

    printf("\nResultant Cipher Text: ");
    for (i = 0, j = 0; i < strlen(input); i++, j++) {
        if (j >= strlen(key))
            j = 0;

        printf("%c", 65 + (((toupper(input[i]) - 65) + (toupper(key[j]) - 65)) % 26));
    }
}

void decipher() {
    unsigned int i, j;
    char input[50], key[10];
    int value;

    printf("\n\nEnter Cipher Text: ");
    scanf("%s", input);

    printf("\nEnter the key value: ");
    scanf("%s", key);

    printf("\nDecrypted Plain Text: ");
    for (i = 0, j = 0; i < strlen(input); i++, j++) {
        if (j >= strlen(key))
            j = 0;

        value = (toupper(input[i]) - 64) - (toupper(key[j]) - 64);
        if (value < 0)
            value = value * -1;

        printf("%c", 65 + (value % 26));
    }
}
```
# OUTPUT
![Screenshot 2024-04-05 191458](https://github.com/gsuryanavya/ARUL-OLI.A/assets/133086963/33f3362f-6696-4617-83b2-5b0e2b1503a3)

# RAIL FENCE
```
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main() {
    int i, j, k, l;
    char a[20], c[20], d[20];

    printf("\n\t\t RAIL FENCE TECHNIQUE\n\n");
    printf("Enter the input string: ");
    fgets(a, sizeof(a), stdin);
    l = strlen(a);
    if (a[l - 1] == '\n')
        a[--l] = '\0'; // Remove trailing newline

    /*Ciphering*/
    for (i = 0, j = 0; i < l; i++) {
        if (i % 2 == 0)
            c[j++] = a[i];
    }
    for (i = 0; i < l; i++) {
        if (i % 2 == 1)
            c[j++] = a[i];
    }
    c[j] = '\0';
    printf("\nCipher text after applying rail fence: %s\n", c);

    /*Deciphering*/
    if (l % 2 == 0)
        k = l / 2;
    else
        k = (l / 2) + 1;

    for (i = 0, j = 0; i < k; i++) {
        d[j] = c[i];
        j = j + 2;
    }
    for (i = k, j = 1; i < l; i++) {
        d[j] = c[i];
        j = j + 2;
    }
    d[l] = '\0';
    printf("Text after decryption: %s\n", d);

    return 0;
}
```
# OUTPUT
![Screenshot 2024-04-05 191803](https://github.com/gsuryanavya/ARUL-OLI.A/assets/133086963/270493d4-0812-40c0-92cd-bf67edf7c719)

# RSA
```
#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>

long int p, q, n, t, flag, e[100], d[100], temp[100], j, m[100], en[100], i;
char msg[100];

int prime(long int);
void ce();
long int cd(long int);
void encrypt();
void decrypt();

int main() {
    printf("\nENTER FIRST PRIME NUMBER\n");
    scanf("%ld", &p);
    flag = prime(p);
    if (flag == 0 || p <= 1) {
        printf("\nWRONG INPUT\n");
        exit(0);
    }
    printf("\nENTER ANOTHER PRIME NUMBER\n");
    scanf("%ld", &q);
    flag = prime(q);
    if (flag == 0 || q <= 1 || p == q) {
        printf("\nWRONG INPUT\n");
        exit(0);
    }
    printf("\nENTER MESSAGE\n");
    fflush(stdin);
    scanf("%s", msg);

    for (i = 0; msg[i] != '\0'; i++)
        m[i] = msg[i];
    n = p * q;
    t = (p - 1) * (q - 1);
    ce();
    printf("\nPOSSIBLE VALUES OF e AND d ARE\n");
    for (i = 0; i < j - 1; i++)
        printf("\n%ld\t%ld", e[i], d[i]);
    encrypt();
    decrypt();
    return 0;
}

int prime(long int pr) {
    int i;
    if (pr == 2)
        return 1;
    if (pr % 2 == 0)
        return 0;
    for (i = 3; i <= sqrt(pr); i += 2) {
        if (pr % i == 0)
            return 0;
    }
    return 1;
}

void ce() {
    int k;
    k = 0;
    for (i = 2; i < t; i++) {
        if (t % i == 0)
            continue;
        flag = prime(i);
        if (flag == 1 && i != p && i != q) {
            e[k] = i;
            flag = cd(e[k]);
            if (flag > 0) {
                d[k] = flag;
                k++;
            }
            if (k == 99)
                break;
        }
    }
    j = k;
}

long int cd(long int x) {
    long int k = 1;
    while (1) {
        k = k + t;
        if (k % x == 0)
            return (k / x);
    }
}

void encrypt() {
    long int pt, ct, key = e[0], k, len;
    i = 0;
    len = strlen(msg);
    while (i != len) {
        pt = m[i];
        pt = pt - 96;
        k = 1;
        for (j = 0; j < key; j++) {
            k = k * pt;
            k = k % n;
        }
        temp[i] = k;
        ct = k + 96;
        en[i] = ct;
        i++;
    }
    en[i] = -1;
    printf("\nTHE ENCRYPTED MESSAGE IS\n");
    for (i = 0; en[i] != -1; i++)
        printf("%c", en[i]);
}

void decrypt() {
    long int pt, ct, key = d[0], k;
    i = 0;
    while (en[i] != -1) {
        ct = temp[i];
        k = 1;
        for (j = 0; j < key; j++) {
            k = k * ct;
            k = k % n;
        }
        pt = k + 96;
        m[i] = pt;
        i++;
    }
    m[i] = -1;
    printf("\nTHE DECRYPTED MESSAGE IS\n");
    for (i = 0; m[i] != -1; i++)
        printf("%c", m[i]);
}
```
# OUTPUT
![Screenshot 2024-04-05 192119](https://github.com/gsuryanavya/ARUL-OLI.A/assets/133086963/d48d9367-ad46-4dd4-9173-62d0d7a17d52)

# IMPLEMENTATION OF MD5
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef union {
    unsigned w;
    unsigned char b[4];
} MD5union;

typedef unsigned DigestArray[4];

unsigned func0(unsigned abcd[]) {
    return (abcd[1] & abcd[2]) | (~abcd[1] & abcd[3]);
}

unsigned func1(unsigned abcd[]) {
    return (abcd[3] & abcd[1]) | (~abcd[3] & abcd[2]);
}

unsigned func2(unsigned abcd[]) {
    return abcd[1] ^ abcd[2] ^ abcd[3];
}

unsigned func3(unsigned abcd[]) {
    return abcd[2] ^ (abcd[1] | ~abcd[3]);
}

typedef unsigned (*DgstFctn)(unsigned a[]);

unsigned *calctable(unsigned *k) {
    double s, pwr;
    int i;
    pwr = pow(2, 32);
    for (i = 0; i < 64; i++) {
        s = fabs(sin(1 + i));
        k[i] = (unsigned)(s * pwr);
    }
    return k;
}

unsigned rol(unsigned r, short N) {
    unsigned mask1 = (1 << N) - 1;
    return ((r >> (32 - N)) & mask1) | ((r << N) & ~mask1);
}

unsigned *md5(const char *msg, int mlen) {
    static DigestArray h0 = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    static DgstFctn ff[] = {&func0, &func1, &func2, &func3};
    static short M[] = {1, 5, 3, 7};
    static short O[] = {0, 1, 5, 0};
    static short rot0[] = {7, 12, 17, 22};
    static short rot1[] = {5, 9, 14, 20};
    static short rot2[] = {4, 11, 16, 23};
    static short rot3[] = {6, 10, 15, 21};
    static short *rots[] = {rot0, rot1, rot2, rot3};
    static unsigned kspace[64];
    static unsigned *k = NULL;
    static DigestArray h;
    DigestArray abcd;
    DgstFctn fctn;
    short m, o, g;
    unsigned f;
    short *rotn;
    union {
        unsigned w[16];
        char b[64];
    } mm;

    int os = 0;
    int grp, grps, q, p;
    unsigned char *msg2;
    if (k == NULL) k = calctable(kspace);

    for (q = 0; q < 4; q++) h[q] = h0[q]; // initialize
    grps = 1 + (mlen + 8) / 64;
    msg2 = malloc(64 * grps);
    memcpy(msg2, msg, mlen);
    msg2[mlen] = (unsigned char)0x80;
    q = mlen + 1;
    while (q < 64 * grps) {
        msg2[q] = 0;
        q++;
    }
    {
        MD5union u;
        u.w = 8 * mlen;
        q -= 8;
        memcpy(msg2 + q, &u.w, 4);
    }

    for (grp = 0; grp < grps; grp++) {
        memcpy(mm.b, msg2 + os, 64);

        for (q = 0; q < 4; q++) abcd[q] = h[q];
        for (p = 0; p < 4; p++) {
            fctn = ff[p];
            rotn = rots[p];
            m = M[p];
            o = O[p];
            for (q = 0; q < 16; q++) {
                g = (m * q + o) % 16;
                f = abcd[1] + rol(abcd[0] + fctn(abcd) + k[q + 16 * p] + mm.w[g], rotn[q % 4]);
                abcd[0] = abcd[3];
                abcd[3] = abcd[2];
                abcd[2] = abcd[1];
                abcd[1] = f;
            }
        }
        for (p = 0; p < 4; p++) h[p] += abcd[p];
        os += 64;
    }
    return h;
}

int main() {
    int j, k;
    const char *msg = "The quick brown fox jumps over the lazy dog";
    unsigned *d = md5(msg, strlen(msg));
    MD5union u;

    printf("\t MD5 ENCRYPTION ALGORITHM IN C \n\n");
    printf("Input String to be Encrypted using MD5 : \n\t%s\n", msg);
    printf("\n\nThe MD5 code for input string is: \n");
    printf("\t= 0x");
    for (j = 0; j < 4; j++) {
        u.w = d[j];
        for (k = 0; k < 4; k++) printf("%02x", u.b[k]);
    }
    printf("\n\n\t MD5 Encryption Successfully Completed!!!\n\n");

    return 0;
}
```
# OUTPUT
![Screenshot 2024-04-05 200005](https://github.com/gsuryanavya/ARUL-OLI.A/assets/133086963/f4ce36a9-41fc-464f-8690-9537f1b71664)

# IMPLEMENTATION OF SHA-1
```
import java.security.*;

public class SHA1 {
    public static void main(String[] a) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            System.out.println("Message digest object info: ");
            System.out.println(" Algorithm = " + md.getAlgorithm());
            System.out.println(" Provider = " + md.getProvider());
            System.out.println(" ToString = " + md.toString());

            String input = "";
            md.update(input.getBytes());
            byte[] output = md.digest();
            System.out.println();
            System.out.println("SHA-1(\"" + input + "\") = " + bytesToHex(output));

            input = "abc";
            md.update(input.getBytes());
            output = md.digest();
            System.out.println();
            System.out.println("SHA-1(\"" + input + "\") = " + bytesToHex(output));

            input = "abcdefghijklmnopqrstuvwxyz";
            md.update(input.getBytes());
            output = md.digest();
            System.out.println();
            System.out.println("SHA-1(\"" + input + "\") = " + bytesToHex(output));
            System.out.println();
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        }
    }

    public static String bytesToHex(byte[] b) {
        char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        StringBuilder buf = new StringBuilder();
        for (byte aB : b) {
            buf.append(hexDigit[(aB >> 4) & 0x0f]);
            buf.append(hexDigit[aB & 0x0f]);
        }
        return buf.toString();
    }
}
```
# OUTPUT
![Screenshot 2024-04-05 200746](https://github.com/gsuryanavya/ARUL-OLI.A/assets/133086963/a70b0865-12cb-4625-8cef-495e0436fcd9)







