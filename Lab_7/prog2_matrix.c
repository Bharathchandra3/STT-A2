/*
 * Program: Matrix Operations
 * Complexity: Nested loops and multidimensional arrays
 */

#include <stdio.h>
#include <stdlib.h>

#define SIZE 5

// Global matrices
int matA[SIZE][SIZE];
int matB[SIZE][SIZE];
int result[SIZE][SIZE];

void initializeMatrices() {
    int i, j;
    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            matA[i][j] = i + j;
            matB[i][j] = i * j;
            if(matB[i][j] == 0) matB[i][j] = 1; // Avoid zero for variety
        }
    }
}

void printResult(char* label) {
    int i, j;
    printf("Matrix: %s\n", label);
    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            printf("%4d ", result[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

int main() {
    int i, j, k;
    int operation_code = 1;

    printf("--- Matrix Operations Tool ---\n");
    initializeMatrices();

    // Operation 1: Addition
    if (operation_code == 1) {
        printf("Performing Addition...\n");
        for (i = 0; i < SIZE; i++) {
            for (j = 0; j < SIZE; j++) {
                result[i][j] = matA[i][j] + matB[i][j];
            }
        }
        printResult("A + B");
    }

    // Operation 2: Multiplication (O(n^3) complexity)
    operation_code = 2; // Change state
    if (operation_code == 2) {
        printf("Performing Multiplication...\n");
        // Reset result
        for(i=0; i<SIZE; i++) 
            for(j=0; j<SIZE; j++) 
                result[i][j] = 0;

        // Multiply
        for (i = 0; i < SIZE; i++) {
            for (j = 0; j < SIZE; j++) {
                for (k = 0; k < SIZE; k++) {
                    result[i][j] += matA[i][k] * matB[k][j];
                }
            }
        }
        printResult("A * B");
    }

    // Operation 3: Transpose of Matrix A
    printf("Performing Transpose of A...\n");
    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            result[j][i] = matA[i][j];
        }
    }
    printResult("Transpose A");

    // Operation 4: Diagonal Sum Analysis
    int diag_sum_main = 0;
    int diag_sum_anti = 0;
    
    for(i=0; i<SIZE; i++) {
        diag_sum_main += matA[i][i];
        diag_sum_anti += matA[i][SIZE - i - 1];
    }
    
    printf("Main Diagonal Sum: %d\n", diag_sum_main);
    printf("Anti-Diagonal Sum: %d\n", diag_sum_anti);

    if(diag_sum_main > diag_sum_anti) {
        printf("Main diagonal is dominant.\n");
    } else {
        printf("Anti-diagonal is dominant or equal.\n");
    }

    // Operation 5: Scalar Multiplication Loop
    int scalar = 5;
    int count_even = 0;
    
    printf("Applying scalar multiplication by %d to last result...\n", scalar);
    for(i=0; i<SIZE; i++) {
        for(j=0; j<SIZE; j++) {
            result[i][j] = result[i][j] * scalar;
            if(result[i][j] % 2 == 0) {
                count_even++;
            }
        }
    }
    printf("Count of even numbers in scaled matrix: %d\n", count_even);

    return 0;
}
