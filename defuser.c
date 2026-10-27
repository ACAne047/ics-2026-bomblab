#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/* Write exactly count unsigned decimal integers, separated by spaces. */
static int write_answer(char *out, size_t cap,
                        const uint32_t *values, size_t count) {
    size_t used = 0;

    if (out == NULL || values == NULL || cap == 0 || count == 0) return 1;

    out[0] = '\0';
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used,
                            "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return 0;
}

/* All arithmetic below intentionally wraps modulo 2^32. */
static uint32_t rol32(uint32_t value, unsigned bits) {
    bits &= 31u;
    return (uint32_t)((value << bits) | (value >> ((32u - bits) & 31u)));
}

static uint32_t ror32(uint32_t value, unsigned bits) {
    bits &= 31u;
    return (uint32_t)((value >> bits) | (value << ((32u - bits) & 31u)));
}

static uint32_t fold64(uint64_t value) {
    return (uint32_t)value ^ (uint32_t)(value >> 32);
}

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    uint32_t high = (uint32_t)(challenge >> 32);
    uint32_t step1 = (high + UINT32_C(4) * (uint32_t)(challenge >> 16))
                     ^ UINT32_C(0x1134);
    uint32_t step0 = (high ^ UINT32_C(0xee51))
                     + UINT32_C(8) * (uint32_t)challenge;

    values[0] = step0 ^ (step1 + UINT32_C(0xc21d));
    return write_answer(out, cap, values, 1);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    values[0] = UINT32_C(2) * ((uint32_t)(challenge >> 47) & UINT32_C(255))
                + UINT32_C(3);
    for (unsigned i = 1; i < 6; ++i) {
        uint32_t delta = (uint32_t)(challenge >> (21u + 3u * i)) & UINT32_C(31);
        values[i] = (values[i - 1] + delta) ^ (UINT32_C(10) * i);
    }
    return write_answer(out, cap, values, 6);
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    uint32_t index = (uint32_t)challenge & UINT32_C(7);
    uint32_t x = (uint32_t)(challenge >> 3) ^ (uint32_t)(challenge >> 32);

    values[0] = index;
    /* The switch order differs from the numeric suffixes of p3_case_N. */
    switch (index) {
        case 0: values[1] = (x >> 2) + (x ^ UINT32_C(0xae7a)); break;
        case 1: values[1] = (x >> 1) + (x ^ UINT32_C(0x314e)); break;
        case 2: values[1] = (UINT32_C(4) * x) ^ UINT32_C(0x4c04); break;
        case 3: values[1] = (UINT32_C(2) * x) ^ UINT32_C(0x542a); break;
        case 4: values[1] = UINT32_C(5) * x + UINT32_C(61838); break;
        case 5: values[1] = UINT32_C(5) * x + UINT32_C(261225); break;
        case 6: values[1] = UINT32_C(3) * x + UINT32_C(55940); break;
        case 7: values[1] = UINT32_C(5) * x + UINT32_C(316995); break;
    }
    return write_answer(out, cap, values, 2);
}

static uint32_t p4_walk(uint32_t target, uint32_t low,
                        uint32_t high, uint32_t salt) {
    uint32_t middle = low + ((high - low) >> 1);
    uint32_t child;

    if (middle == target) return salt ^ (middle + UINT32_C(81));
    if (target < middle) {
        child = p4_walk(target, low, middle - UINT32_C(1), salt);
        return (middle + salt) ^ (UINT32_C(5) * child) ^ UINT32_C(0x15);
    }
    child = p4_walk(target, middle + UINT32_C(1), high, salt);
    return (middle + salt) ^ (UINT32_C(5) * child) ^ UINT32_C(1);
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    uint32_t salt = (uint32_t)(challenge >> 32) ^ (uint32_t)(challenge >> 7);

    values[0] = p4_walk((uint32_t)challenge & UINT32_C(127), 0, 127, salt);
    return write_answer(out, cap, values, 1);
}

struct p5_node {
    unsigned next;
    uint32_t value;
    uint32_t salt;
};

/* Indices correspond to (original address - 0x405ba0) / 16. */
static const struct p5_node p5_nodes[12] = {
    {10, 2834, 37899}, {6, 2110, 50451}, {5, 262, 20605},
    {0, 2434, 8976}, {11, 1606, 61672}, {9, 2673, 25107},
    {4, 550, 59135}, {2, 898, 5417}, {3, 1839, 56710},
    {1, 1130, 21168}, {7, 1412, 50452}, {12, 102, 41699}
};

static const unsigned p5_heads[8] = {8, 3, 0, 10, 7, 2, 5, 9};

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    unsigned node = p5_heads[challenge & UINT64_C(7)];
    unsigned steps = (unsigned)((challenge >> 3) & UINT64_C(3)) + 1u;
    uint32_t accumulator = (uint32_t)(challenge >> 32)
                            ^ (uint32_t)(challenge >> 6) ^ UINT32_C(0x8562);

    for (unsigned i = 0; i < steps; ++i) {
        const struct p5_node *current = &p5_nodes[node];
        accumulator = current->value ^ (UINT32_C(5) * (current->salt + accumulator));
        values[1] = current->value;
        node = current->next;
    }
    values[0] = accumulator;
    return write_answer(out, cap, values, 2);
}

static uint32_t p6_op(unsigned operation, uint32_t x) {
    switch (operation) {
        case 0: return (UINT32_C(5) * x) ^ ((x << 7) + UINT32_C(58988));
        case 1: return (x >> 7) ^ (x + UINT32_C(55571));
        case 2: return ror32(x, 5);
        case 3: return (x ^ (x >> 3)) + UINT32_C(43033);
        case 4: return rol32(x, 3) ^ UINT32_C(0x7d04);
        case 5: return (x ^ UINT32_C(0x335f)) + UINT32_C(4) * x;
        default: return 0;
    }
}

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    static const unsigned operations[8] = {1, 3, 3, 4, 1, 0, 5, 2};
    uint32_t values[MAX_FIELDS] = {0};
    uint32_t x = (uint32_t)(challenge >> 32) ^ (uint32_t)(challenge >> 6);

    x = p6_op(operations[challenge & UINT64_C(7)], x) ^ UINT32_C(0xd596);
    values[0] = p6_op(operations[(challenge >> 3) & UINT64_C(7)], x)
                 + UINT32_C(41495);
    return write_answer(out, cap, values, 1);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    uint32_t a = fold64(challenge);
    uint32_t b = fold64(context);
    uint32_t selector = (uint32_t)context & UINT32_C(3);
    uint32_t answer = ror32(a ^ b, 7) ^ UINT32_C(0x7c05)
                       ^ (uint32_t)(context >> 16) ^ (UINT32_C(5892) * selector);
    uint32_t check = answer ^ ((a >> 7) + b + selector + UINT32_C(27393));
    int size;

    if (out == NULL || cap == 0) return 1;

    /* Exactly 32 filler bytes, then OPEN at offset 32 and integers at 36. */
    size = snprintf(out, cap,
                    "AAAAAAAA" "AAAAAAAA" "AAAAAAAA" "AAAAAAAA"
                    "OPEN%" PRIu32 " %" PRIu32 " %" PRIu32,
                    selector, answer, check);
    return size < 0 || (size_t)size >= cap;
}
