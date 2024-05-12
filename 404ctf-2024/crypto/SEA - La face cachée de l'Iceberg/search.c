#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

// gcc search.c -o search;./search

#define SBOX_SIZE 256

unsigned char SBOX_1[SBOX_SIZE] = {
    0x24, 0xc1, 0x38, 0x30, 0xe7, 0x57, 0xdf, 0x20, 0x3e, 0x99, 0x1a, 0x34, 0xca, 0xd6, 0x52, 0xfd,
    0x40, 0x6c, 0xd3, 0x95, 0x4a, 0x59, 0xf8, 0x77, 0x79, 0x61, 0x0a, 0x56, 0xb9, 0xd2, 0xfc, 0xf1,
    0x07, 0xf5, 0x93, 0xcd, 0x00, 0xb6, 0xcb, 0xa7, 0x63, 0x98, 0x44, 0xbd, 0x5f, 0x92, 0x6b, 0x73,
    0x3c, 0x4e, 0xa2, 0x97, 0x0b, 0x01, 0x83, 0xa3, 0xee, 0xe5, 0x45, 0x67, 0xf4, 0x13, 0xad, 0x8b,
    0xbb, 0x0c, 0x72, 0xb4, 0x2a, 0x3a, 0xc5, 0x84, 0xec, 0x9f, 0x14, 0xc0, 0xc4, 0x16, 0x31, 0xd9,
    0xab, 0x9e, 0x0e, 0x1d, 0x7c, 0x48, 0x1b, 0x05, 0x1c, 0xea, 0xa5, 0xf0, 0x8f, 0x85, 0x50, 0x2c,
    0x35, 0xbf, 0x26, 0x28, 0x7b, 0xe2, 0xaa, 0xf9, 0x4f, 0xe3, 0xcc, 0x2e, 0x11, 0x76, 0xb1, 0x8d,
    0xd4, 0x5e, 0xaf, 0xe8, 0x42, 0xb0, 0x6d, 0x65, 0x82, 0x6a, 0x58, 0x8a, 0xdd, 0x7e, 0x22, 0xd8,
    0xe0, 0x4c, 0x2d, 0xcf, 0x75, 0x12, 0x8e, 0xb2, 0xbc, 0x36, 0x2b, 0x25, 0xe1, 0x78, 0xfa, 0xa9,
    0x69, 0x81, 0x89, 0x5b, 0x7d, 0xde, 0xdb, 0x21, 0x5d, 0xd7, 0xeb, 0xac, 0xb3, 0x41, 0x66, 0x6e,
    0x9c, 0xef, 0xc3, 0x17, 0x15, 0xc7, 0xda, 0x32, 0x0f, 0xb8, 0xb7, 0x71, 0x39, 0x29, 0x87, 0xc6,
    0xe9, 0x1f, 0xf3, 0xa6, 0x86, 0x8c, 0x2f, 0x53, 0x9d, 0xa8, 0x1e, 0x0d, 0x4b, 0x7f, 0x06, 0x18,
    0x9b, 0x60, 0xbe, 0x47, 0x91, 0x5c, 0x70, 0x68, 0xf6, 0x04, 0xce, 0x90, 0xb5, 0x03, 0xa4, 0xc8,
    0xe6, 0xed, 0x64, 0x46, 0x10, 0xf7, 0x88, 0xae, 0x4d, 0x3f, 0x94, 0xa1, 0x02, 0x08, 0xa0, 0x80,
    0x9a, 0x3d, 0x37, 0x19, 0xd5, 0xc9, 0xfe, 0x51, 0xc2, 0x27, 0x33, 0x3b, 0x54, 0xe4, 0x23, 0xdc,
    0x62, 0x7a, 0x55, 0x09, 0xd1, 0xba, 0xf2, 0xff, 0x6f, 0x43, 0x96, 0xd0, 0x5a, 0x49, 0x74, 0xfb,
};

unsigned char SBOX_2[SBOX_SIZE] = {
    0x24, 0xc1, 0x38, 0x30, 0xe7, 0x57, 0xdf, 0x20, 0x3e, 0x99, 0x1a, 0x34, 0xca, 0xd6, 0x52, 0xfd,
    0x40, 0x6c, 0xd3, 0x3d, 0x4a, 0x59, 0xf8, 0x77, 0xfb, 0x61, 0x0a, 0x56, 0xb9, 0xd2, 0xfc, 0xf1,
    0x07, 0xf5, 0x93, 0xcd, 0x00, 0xb6, 0x62, 0xa7, 0x63, 0xfe, 0x44, 0xbd, 0x5f, 0x92, 0x6b, 0x68,
    0x03, 0x4e, 0xa2, 0x97, 0x0b, 0x60, 0x83, 0xa3, 0x02, 0xe5, 0x45, 0x67, 0xf4, 0x13, 0x08, 0x8b,
    0x10, 0xce, 0xbe, 0xb4, 0x2a, 0x3a, 0x96, 0x84, 0xc8, 0x9f, 0x14, 0xc0, 0xc4, 0x6f, 0x31, 0xd9,
    0xab, 0xae, 0x0e, 0x64, 0x7c, 0xda, 0x1b, 0x05, 0xa8, 0x15, 0xa5, 0x90, 0x94, 0x85, 0x71, 0x2c,
    0x35, 0x19, 0x26, 0x28, 0x53, 0xe2, 0x7f, 0x3b, 0x2f, 0xa9, 0xcc, 0x2e, 0x11, 0x76, 0xed, 0x4d,
    0x87, 0x5e, 0xc2, 0xc7, 0x80, 0xb0, 0x6d, 0x17, 0xb2, 0xff, 0xe4, 0xb7, 0x54, 0x9d, 0xb8, 0x66,
    0x74, 0x9c, 0xdb, 0x36, 0x47, 0x5d, 0xde, 0x70, 0xd5, 0x91, 0xaa, 0x3f, 0xc9, 0xd8, 0xf3, 0xf2,
    0x5b, 0x89, 0x2d, 0x22, 0x5c, 0xe1, 0x46, 0x33, 0xe6, 0x09, 0xbc, 0xe8, 0x81, 0x7d, 0xe9, 0x49,
    0xe0, 0xb1, 0x32, 0x37, 0xea, 0x5a, 0xf6, 0x27, 0x58, 0x69, 0x8a, 0x50, 0xba, 0xdd, 0x51, 0xf9,
    0x75, 0xa1, 0x78, 0xd0, 0x43, 0xf7, 0x25, 0x7b, 0x7e, 0x1c, 0xac, 0xd4, 0x9a, 0x2b, 0x42, 0xe3,
    0x4b, 0x01, 0x72, 0xd7, 0x4c, 0xfa, 0xeb, 0x73, 0x48, 0x8c, 0x0c, 0xf0, 0x6a, 0x23, 0x41, 0xec,
    0xb3, 0xef, 0x1d, 0x12, 0xbb, 0x88, 0x0d, 0xc3, 0x8d, 0x4f, 0x55, 0x82, 0xee, 0xad, 0x86, 0x06,
    0xa0, 0x95, 0x65, 0xbf, 0x7a, 0x39, 0x98, 0x04, 0x9b, 0x9e, 0xa4, 0xc6, 0xcf, 0x6e, 0xdc, 0xd1,
    0xcb, 0x1f, 0x8f, 0x8e, 0x3c, 0x21, 0xa6, 0xb5, 0x16, 0xaf, 0xc5, 0x18, 0x1e, 0x0f, 0x29, 0x79,
};

uint64_t f(uint64_t block) {
    uint64_t b1, b2, b3, b4, b5, b6, b7, b8;

    b1 = (block >> 56);
    b2 = (block >> 48) & 0xff;
    b3 = (block >> 40) & 0xff;
    b4 = (block >> 32) & 0xff;
    b5 = (block >> 24) & 0xff;
    b6 = (block >> 16) & 0xff;
    b7 = (block >> 8) & 0xff;
    b8 = block & 0xff;

    b2 ^= b3;
    b1 ^= b2;
    b1 = SBOX_1[b1];
    b2 ^= b1;
    b2 = SBOX_2[b2];
    b3 ^= b2;
    b3 = SBOX_2[b3];
    b3 ^= b1;
    b4 ^= b5;
    b4 = SBOX_2[b4];
    b5 ^= b4;
    b5 = SBOX_1[b5];
    b7 ^= b6;
    b6 = SBOX_1[b6];
    b7 ^= b6;
    b7 = SBOX_2[b7];
    b8 ^= b7;
    b6 ^= b7;
    b8 = SBOX_1[b8];

    return (b2 << 56) + (b3 << 48) + (b6 << 40) + (b1 << 32) + (b4 << 24) + (b8 << 16) + (b5 << 8) + b7;
}

typedef uint64_t (*UnShuffleFunc)(uint64_t);

uint64_t unshuffle_bits_left(uint64_t y) {
    uint64_t b1, b2, b3, b4, b5, b6, b7, b8;

    b2 = (y >> 56);
    b3 = (y >> 48) & 0xff;
    b6 = (y >> 40) & 0xff;
    b1 = (y >> 32) & 0xff;
    b4 = (y >> 24) & 0xff;
    b8 = (y >> 16) & 0xff;
    b5 = (y >> 8) & 0xff;
    b7 = y & 0xff;

    uint64_t result = (b2 << 16) | (b3 << 8) | (b1 << 0);
    // uint64_t result = (b1 << 16) | (b2 << 8) | (b3 << 0);
    return result;
}


uint64_t unshuffle_bits_mid(uint64_t y) {
    uint64_t b1, b2, b3, b4, b5, b6, b7, b8;

    b2 = (y >> 56);
    b3 = (y >> 48) & 0xff;
    b6 = (y >> 40) & 0xff;
    b1 = (y >> 32) & 0xff;
    b4 = (y >> 24) & 0xff;
    b8 = (y >> 16) & 0xff;
    b5 = (y >> 8) & 0xff;
    b7 = y & 0xff;

    uint64_t result = (b4 << 8) | (b5 << 0);
    return result;
}


uint64_t unshuffle_bits_right(uint64_t y) {
    uint64_t b1, b2, b3, b4, b5, b6, b7, b8;

    b2 = (y >> 56);
    b3 = (y >> 48) & 0xff;
    b6 = (y >> 40) & 0xff;
    b1 = (y >> 32) & 0xff;
    b4 = (y >> 24) & 0xff;
    b8 = (y >> 16) & 0xff;
    b5 = (y >> 8) & 0xff;
    b7 = y & 0xff;

    uint64_t result = (b6 << 16) | (b8 << 8) | (b7 << 0);
    return result;
}

void search_diff(unsigned limit, int try, int bound, int and, int shift, char* position, UnShuffleFunc unshuffle, bool debug) {
    printf("\n\nStarting search for %s position ...\n", position);

    for (unsigned diff = 1; diff < limit; diff++) {

        int success = 0;

        for (int c = 0; c < try; c++){

            // Genère 2 input de différence "diff"
            int p1 = rand() & and; 
            int p2 = (p1 ^ diff) & and; 

            // Pad à droite avec des 0 si nécessaire
            uint64_t x1 = (uint64_t)p1 << shift;
            uint64_t x2 = (uint64_t)p2 << shift;

            // x -> f(x)
            uint64_t y1_original = f(x1);
            uint64_t y2_original = f(x2);

            // Remet dans l'ordre => pas utile car même ordre pour les 2 => pas d'importance
            uint64_t y1 = unshuffle(y1_original);
            uint64_t y2 = unshuffle(y2_original);

            // Différenciel de sortie.
            unsigned diff2 = y1^y2;

            // Si les 2 différenciels sont égaux => +1
            if (diff == diff2) {
                success += 1;

                if (debug) {                    
                    printf("%5s: x1=%20llu | x2=%20llu | diff_in:%8u => f1=%20llu | f2=%20llu | diff_out:%8u\n",
                position,x1, x2, diff, y1_original, y2_original, diff2);

                }

            }

        }

        // Si un différenciel dépasse le seuil, c'est un bon différentiel
        if (success > bound) {
            printf("[%s] Potential differential: %d\n", position,diff);
        }

    }
}

void verify_diff_with_const(unsigned limit, int try, unsigned int *candidates, int and, int shift, char* position, UnShuffleFunc unshuffle, uint64_t target) {
    printf("\n\nStarting search for %s position ...\n", position);

    int array_length = sizeof(candidates) / sizeof(candidates[0]);

    for (int i = 0; i < array_length; ++i) {
        unsigned diff = candidates[i];

        int success = 0;

        for (int c = 0; c < try; c++){

            // Genère 2 input de différence "diff"
            int p1 = rand() & and; 
            int p2 = (p1 ^ diff) & and; 

            // Pad à droite avec des 0 si nécessaire
            uint64_t x1 = (uint64_t)p1 << shift;
            uint64_t x2 = (uint64_t)p2 << shift;

            // x -> f(x)
            uint64_t y1_original = f(x1);
            uint64_t y2_original = f(x2);

            // Remet dans l'ordre => pas utile car même ordre pour les 2 => pas d'importance
            uint64_t y1 = unshuffle(y1_original);
            uint64_t y2 = unshuffle(y2_original);

            // Différenciel de sortie.
            unsigned diff2 = y1^y2;

            // Si les 2 différenciels sont égaux => +1
            if (diff2 == target){
                success += 1;

                printf("%5s: x1=%20llu | x2=%20llu | diff_in:%8u => f1=%20llu | f2=%20llu | diff_out:%8u | Occurence: %2d\n",
                position,x1, x2, diff, y1_original, y2_original, target, success);
                
            }
        }

    }
}


void search_diff_with_const(unsigned limit, int try, int bound, int and, int shift, char* position, UnShuffleFunc unshuffle, bool debug, uint64_t target) {
    printf("\n\nStarting search for %s position ...\n", position);

    for (unsigned diff = 1; diff < limit; diff++) {

        int success = 0;

        for (int c = 0; c < try; c++){

            // Genère 2 input de différence "diff"
            int p1 = rand() & and; 
            int p2 = (p1 ^ diff) & and; 

            // Pad à droite avec des 0 si nécessaire
            uint64_t x1 = (uint64_t)p1 << shift;
            uint64_t x2 = (uint64_t)p2 << shift;

            // x -> f(x)
            uint64_t y1_original = f(x1);
            uint64_t y2_original = f(x2);

            // Remet dans l'ordre => pas utile car même ordre pour les 2 => pas d'importance
            uint64_t y1 = unshuffle(y1_original);
            uint64_t y2 = unshuffle(y2_original);

            // Différenciel de sortie.
            unsigned diff2 = y1^y2;

            // Si les 2 différenciels sont égaux => +1
            if (diff2 == target){
                success += 1;

                if (debug) {
                    printf("%5s: x1=%20llu | x2=%20llu | diff_in:%8u => f1=%20llu | f2=%20llu | diff_out:%8u | Occurence: %2d\n",
                position,x1, x2, diff, y1_original, y2_original, target, success);
                }

            }

        }

        // Si un différenciel dépasse le seuil, c'est un bon différentiel
        if (success > bound) {
            printf("[%s] Potential differential: %d\n", position,diff);
        }

    }
}


void search_identity(uint64_t limit, int shift, char* position, UnShuffleFunc unshuffle) {
    printf("\n\nStarting search identity for %s function ...\n", position);

    for (uint64_t k = 1; k < limit; k++) {

        uint64_t x = (uint64_t)k << shift;
        uint64_t y = f(x);

        if (k == (uint64_t)(unshuffle(y))) {
            printf("%5s: base=%20llu => x=%20llu | f(x)=%20llu\n",
                position, k, x, y);
        }
        
    }
}

int main() {
    srand(time(NULL));

    

    // // Search for differentials | Bounds are 7/100 here
    search_diff_with_const(
        255*255*255,            // Nombre de diff possible
        500,                    // Nombre de test par diff
        25,                     // Nombre d'égalité valide pour 1 diff
        0xFFFFFF,               // Shifting pour la génération du nombre 
        (64-3*8),               // Décallage pour la génération du nombre (Nombre de 0 à droite du nombre généré)
        "LEFT",                 // Nom de la partie qu'on bf
        unshuffle_bits_left,    // Fonction pour ré-ordonner les bytes de sortie.
        true,                   // Debug mode to see when a diffrencial match
        (uint64_t)((3 << 16) | (3 << 8) | (3 << 0)) // F(x^delta)^F(x) = const au lieu de F(x^delta)^F(x) = delta
    );

    // unsigned int candidates[] = {
    //     5089027,
    //     5153795,
    //     5619459,
    //     6914819,
    //     7773187,
    //     9664771,
    //     13712131,
    //     13975299,
    //     15735299
    // };

    // verify_diff_with_const(
    //     255*255*255,            // Nombre de diff possible
    //     500,                    // Nombre de test par diff
    //     candidates,             // Candidats à tester
    //     0xFFFFFF,               // Shifting pour la génération du nombre 
    //     (64-3*8),               // Décallage pour la génération du nombre (Nombre de 0 à droite du nombre généré)
    //     "LEFT",                 // Nom de la partie qu'on bf
    //     unshuffle_bits_left,    // Fonction pour ré-ordonner les bytes de sortie.
    //     (uint64_t)((3 << 16) | (3 << 8) | (3 << 0)) // F(x^delta)^F(x) = const au lieu de F(x^delta)^F(x) = delta

    // );


    

    // Search for x such as f(x)=x for parts of f
    // search_identity(
    //     255*255*255,            // Range de x
    //     (64-3*8),               // Décallage pour la génération du nombre (Nombre de 0 à droite du nombre généré)
    //     "LEFT",                 // Nom de la partie qu'on bf
    //     unshuffle_bits_left     // Fonction pour ré-ordonner les bytes de sortie.
    // );

    // search_identity(
    //     255*255,
    //     (64-5*8),
    //     "MID",
    //     unshuffle_bits_left
    // );

    // search_identity(
    //     255*255*255,
    //     (64-8*8),
    //     "RIGHT",
    //     unshuffle_bits_right
    // );





    // search_diff(
    // 255*255*255,            // Nombre de diff possible
    // 100,                    // Nombre de test par diff
    // 5,                      // Nombre d'égalité valide pour 1 diff
    // 0xFFFFFF,               // Shifting pour la génération du nombre 
    // (64-3*8),               // Décallage pour la génération du nombre (Nombre de 0 à droite du nombre généré)
    // "LEFT",                 // Nom de la partie qu'on bf
    // unshuffle_bits_left,    // Fonction pour ré-ordonner les bytes de sortie.
    // true,                   // Debug mode to see when a diffrencial match
    // );

    // search_diff(
    //     255*255,
    //     1000,
    //     70,
    //     0xFFFF,
    //     (64-5*8),
    //     "MID",
    //     unshuffle_bits_mid,
    //     false
    // );

    // search_diff(
    //     255*255*255,
    //     1000,
    //     70,
    //     0xFFFFFF,
    //     (64-8*8),
    //     "RIGHT",
    //     unshuffle_bits_right,
    //     false
    // );



    return 0;
}

// 14497539

// Starting search identity for LEFT function ...
//  LEFT: base=                9216 => x=   10133099161583616 | f(x)=   10172682186522624
//  LEFT: base=                9252 => x=   10172681580183552 | f(x)=   10172836805345280
//  LEFT: base=             2359296 => x= 2594073385365405696 | f(x)= 2594112968390344704
//  LEFT: base=             2359332 => x= 2594112967784005632 | f(x)= 2594113123009167360


// Starting search identity for MID function ...
//   MID: base=                  36 => x=           603979776 | f(x)=      39737039781888


// Starting search identity for RIGHT function ...
// RIGHT: base=                9252 => x=                9252 | f(x)=        155225161764
// RIGHT: base=             2368548 => x=             2368548 | f(x)=      39737643761700