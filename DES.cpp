#include "des_64.h"
#include "general_methods.h"
#include "key_generation.h"

uint8_t *generate_left_partition(uint8_t *initial_permutation_text)
{
    uint8_t *left_partition = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    for (int i = 0; i < 32; i++)
    {
        left_partition[i] = initial_permutation_text[i];
    }
    return left_partition;
}

uint8_t *generate_right_partition(uint8_t *initial_permutation_text)
{
    uint8_t *right_partition = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    for (int i = 0; i < 32; i++)
    {
        right_partition[i] = initial_permutation_text[i + 32];
    }
    return right_partition;
}

uint8_t *expand_partition_32_48(uint8_t *partition)
{
    uint8_t *expanded_partition = (uint8_t *)malloc(sizeof(uint8_t) * 48);
    for (int i = 0; i < 48; i++)
    {
        expanded_partition[i] = partition[PARTITION_EXPAND_32_TO_48[i] - 1];
    }
    return expanded_partition;
}

uint8_t *function_f(uint8_t *right_partition, uint8_t *key)
{
    uint8_t *expanded_partition = expand_partition_32_48(right_partition);
    uint8_t *key_xor_partition = xor_array(expanded_partition, key, 48);
    uint8_t **div_key_partition = (uint8_t **)malloc(sizeof(uint8_t *) * 8);
    for (int i = 0; i < 8; i++)
    {
        div_key_partition[i] = (uint8_t *)malloc(sizeof(uint8_t) * 6);
    }

    int first_index = 0;
    int second_index = 0;
    for (int i = 0; i < 48; i++)
    {
        if (second_index > 5)
        {
            first_index++;
            second_index = 0;
        }
        div_key_partition[first_index][second_index] = key_xor_partition[i];
        second_index++;
    }

    uint8_t **comp_key_partition = (uint8_t **)malloc(sizeof(uint8_t *) * 8);
    for (int i = 0; i < 8; i++)
    {
        comp_key_partition[i] = (uint8_t *)malloc(sizeof(uint8_t) * 4);
        comp_key_partition[i] = compress_sbox(div_key_partition[i], i);
    }

    uint8_t *concat_sbox_values = concatenate_sbox(comp_key_partition);
    uint8_t *premute_pbox = permute_pbox(concat_sbox_values);
    return premute_pbox;
}

uint8_t *encrypt(uint8_t *plain_text, uint8_t *key)
{
    uint8_t *initial_permutation_text = initial_permutation(plain_text);
    uint8_t **final_keys = generate_key(key);

    uint8_t **left_partition = (uint8_t **)malloc(sizeof(uint8_t *) * 17);
    uint8_t **right_partition = (uint8_t **)malloc(sizeof(uint8_t **) * 17);
    for (int i = 0; i < 17; i++)
    {
        left_partition[i] = (uint8_t *)malloc(sizeof(uint8_t) * 32);
        right_partition[i] = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    }
    left_partition[0] = generate_left_partition(initial_permutation_text);
    right_partition[0] = generate_right_partition(initial_permutation_text);

    for (int i = 1; i <= 16; i++)
    {
        left_partition[i] = right_partition[i - 1];
        uint8_t *f_value = function_f(right_partition[i - 1], final_keys[i - 1]);
        right_partition[i] = xor_array(left_partition[i - 1], f_value, 32);
    }

    uint8_t *final_text = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    for (int i = 0; i < 64; i++)
    {
        if (i > 31)
        {
            final_text[i] = left_partition[16][i - 32];
        }
        else
        {
            final_text[i] = right_partition[16][i];
        }
    }

    uint8_t *cipher_text = inverse_initial_permutation(final_text);
    return cipher_text;
}

uint8_t *decrypt(uint8_t *cipher_text, uint8_t *key)
{
    uint8_t *initial_permutation_text = initial_permutation(cipher_text);
    uint8_t **final_keys = generate_key(key);

    uint8_t **left_partition = (uint8_t **)malloc(sizeof(uint8_t *) * 17);
    uint8_t **right_partition = (uint8_t **)malloc(sizeof(uint8_t **) * 17);
    for (int i = 0; i < 17; i++)
    {
        left_partition[i] = (uint8_t *)malloc(sizeof(uint8_t) * 32);
        right_partition[i] = (uint8_t *)malloc(sizeof(uint8_t) * 32);
    }
    left_partition[0] = generate_left_partition(initial_permutation_text);
    right_partition[0] = generate_right_partition(initial_permutation_text);

    for (int i = 1; i <= 16; i++)
    {
        left_partition[i] = right_partition[i - 1];
        uint8_t *f_value = function_f(right_partition[i - 1], final_keys[16 - i]);
        right_partition[i] = xor_array(left_partition[i - 1], f_value, 32);
    }

    uint8_t *final_text = (uint8_t *)malloc(sizeof(uint8_t) * 64);
    for (int i = 0; i < 64; i++)
    {
        if (i > 31)
        {
            final_text[i] = left_partition[16][i - 32];
        }
        else
        {
            final_text[i] = right_partition[16][i];
        }
    }

    uint8_t *plain_text = inverse_initial_permutation(final_text);
    return plain_text;
}