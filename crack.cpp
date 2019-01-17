#include <openssl/md5.h>
#include <cstdlib>
#include <bitset>
#include <cstring>
#include <string>
#include <iostream>
#include <iomanip>


using namespace std;

void compute_intermsum(char* psswd, unsigned p_len, char* magic, unsigned m_len, char* salt, unsigned s_len, char* altsum, unsigned a_len, char* intermsum_prealloc); // intermediate_0 sum
void interm_1000(char* psswd, unsigned p_len, char* salt, unsigned s_len, char* intermsum, unsigned i_len, char* interm1000_sum_prealloc); // extends to intermsum to intermediate_1000 sum
void rearrange(char* finalsum, unsigned sum_len, char* partitioned_stuff);
void compute_primitive_md5(char* input, unsigned in_len, char* altsum_prealloc); //return the "primitive" md5 hash of a string

void print_char_hex(char* to_print, unsigned len) {
    for(unsigned i = 0; i < len; ++i)
        cout << hex << setfill('0') << setw(2) << static_cast<int>(to_print[i]) << " ";
    cout << dec << endl;
}

void print_char_reg(char* to_print, unsigned len) {
    for(unsigned i = 0; i < len; ++i)
        cout << (to_print[i]) << " ";
    cout << endl;
}

bool check_pass(char* psswd) { // NOTE: Will only check correctly 6 char passwords
    // char psswd[7] = "bbcdef"; // null terminated (all-ish of them)
    char salt[9] = "hfT7jp2q";
    char hash[23] = "v8XH/MrpaYdagdMgM4yKc.";
    char magic[4] = "$1$";
    // compute alternate sum
    char input[21];
    strcpy(input, psswd);
    strcat(input, salt);
    strcat(input, psswd);
    // print_char_reg(input, 21);
    
    unsigned input_size = 20; // definitely not including the null character at the end
    char altsum_prealloc[16];
    compute_primitive_md5(input, input_size, altsum_prealloc); // computes the altsum

    // print_char_hex(altsum_prealloc, 16);

    // compute intermediate sum
    unsigned psswd_size = 6; // NOTE: COULD BE ONE MORE
    unsigned magic_size = 3; // NOTE: COULD BE ONE MORE
    unsigned salt_size = 8; // NOTE: ALSO COULD BE ONE MORE
    unsigned altsum_size = 16; // I love hardcoded things (even if it will deterministically be 16 forever so I guess this is best practice)
    char intermsum_prealloc[16];  // oNLY WORKS ON PASSWORD SIZES OF 16
    compute_intermsum(psswd, psswd_size, magic, magic_size, salt, salt_size, altsum_prealloc, altsum_size, intermsum_prealloc);

    // print_char_hex(intermsum_prealloc, 16);

    // // remaining calculations to extend intermsum to interm_1000
    char interm1000_sum_prealloc[16]; // I love hardcoded things
    unsigned intermsum_size = 16;
    interm_1000(psswd, psswd_size, salt, salt_size, intermsum_prealloc, intermsum_size, interm1000_sum_prealloc);

    // print_char_hex(interm1000_sum_prealloc, 16);

    /// // rearrange/hash the bytes of the interm_1000
    char partitioned_stuff[23];
    unsigned interm1000_size = 16; // for readibility :'>
    rearrange(interm1000_sum_prealloc, interm1000_size, partitioned_stuff);

    if(strncmp(partitioned_stuff, hash, 22) == 0) {
        return true;
    }
    return false;
    // for (unsigned i = 0; i < 23; ++i) {
    //     cout << partitioned_stuff[i];
    //     if (hash[i] == partitioned_stuff[i]) {
    //         // cout << "Alexxxxxx: " << partitioned_stuff[i];
    //     }
    //     else {
    //         // cout << "boo: " << partitioned_stuff[i] << "\n";
    //     }
    // }
    // cout << endl;
}

bool get_next_pass(char* pass, unsigned num_to_skip) { // return true if pass contains a valid password when returning i.e. when no more passwords to compute, returns false

}

bool get_prev_pass(char* pass, unsigned num_to_skip) { // return true if pass contains a valid password when returning i.e. when no more passwords to compute, returns false

}

int main(int argc, char** argv) { // TODO: 
    char* start = argv[1];
    char direction = argv[2][0];
    unsigned num_to_skip = static_cast<unsigned>(argv[3][0]);

    if(direction == 'l') {
        do {
            if(check_pass(start)) {
                printf("HIT: %s", start);
            }
        } while (get_prev_pass(start, num_to_skip));
    } else if(direction == 'r') {
        do {
            if(check_pass(start)) {
                printf("HIT: %s", start);
            }
        } while (get_next_pass(start, num_to_skip));
    } else {

    }

    // char pass[7] = "bbcdef";
    // cout << check_pass(pass) << endl;
    return 0;
}


// tell each thread where to start, which direction to go in, and how many passwords to skip
void compute_primitive_md5(char* input, unsigned in_len, char* digest) {
    // char digest[16];   //allocate 16 bytes for result, or "digest"
    // char* to_hash;   //allocate space for input 
    // strcpy(to_hash, input.c_str());   //copy input into to_hash
    MD5_CTX* context = new MD5_CTX();
    MD5_Init(context);
    MD5_Update(context, (unsigned char*)(input), in_len);
    MD5_Final((unsigned char*)(digest), context);
    // delete context;
    // MD5((unsigned char*)(input), in_len, (unsigned char*)(digest));    //compute the md5 (which is also the altsum)
    return;    // convert into a string
}

// compute intermediate sum (Intermediate_0)
void compute_intermsum(char* psswd, unsigned p_len, char* magic, unsigned m_len, char* salt, unsigned s_len, char* altsum, unsigned a_len, char* intermsum_prealloc) {
    // concatenate the inputs; altsum is repeated as necessary
    unsigned int wholes = (p_len / a_len);
    unsigned int parts = (p_len % a_len);
    unsigned int tmp_intermsum_len = 0;
    char tmp_intermsum[27];
    char final_intermsum_before_hash_so_hash_this_intermsum[27];
    unsigned int final_intermsum_before_hash_so_hash_this_intermsum_len = 0;

    memcpy(tmp_intermsum, psswd, p_len);
    tmp_intermsum_len += p_len;
    memcpy(tmp_intermsum + tmp_intermsum_len, magic, m_len);
    tmp_intermsum_len += m_len;
    memcpy(tmp_intermsum + tmp_intermsum_len, salt, s_len);
    tmp_intermsum_len += s_len;
    
    for (unsigned int i = 0; i < wholes; ++i) {
        memcpy(tmp_intermsum + tmp_intermsum_len, altsum, a_len);
        tmp_intermsum_len += a_len;
    }
    memcpy(tmp_intermsum + tmp_intermsum_len, altsum, parts);
    tmp_intermsum_len += parts;

    // For each bit in length(password), from low to high and stopping after the most significant set bit such that
    bitset<4> bin_tmp_intermsum(p_len);
    for (unsigned int i = 0; i < 4 ; ++i) {
        if (bin_tmp_intermsum[i] == 0) {
            memcpy(tmp_intermsum + tmp_intermsum_len, psswd, 1);
            ++tmp_intermsum_len;
        }
        else { // if set
            // tmp_intermsum.append(psswd.substr(0, 1));
            tmp_intermsum[tmp_intermsum_len] = '\0';
            ++tmp_intermsum_len;
            // intermsum_prealloc = tmp_intermsum;
            memcpy(final_intermsum_before_hash_so_hash_this_intermsum, tmp_intermsum, tmp_intermsum_len);
            final_intermsum_before_hash_so_hash_this_intermsum_len = tmp_intermsum_len;
        }
    }
    
    // print_char_reg(final_intermsum_before_hash_so_hash_this_intermsum, final_intermsum_before_hash_so_hash_this_intermsum_len);
    compute_primitive_md5(final_intermsum_before_hash_so_hash_this_intermsum, final_intermsum_before_hash_so_hash_this_intermsum_len, intermsum_prealloc);
    return;
}


// remaining calculations (Intermediate_0 extended to Intermediate_1000)
void interm_1000(char* psswd, unsigned p_len, char* salt, unsigned s_len, char* intermsum, unsigned i_len, char* interm1000_sum_prealloc) {
    char working_final[i_len + p_len + p_len + s_len];
    unsigned working_final_len = 0;
    memcpy(interm1000_sum_prealloc, intermsum, i_len);
    // char tmptmptmp[16];

    for (unsigned i = 0; i < 1000; ++i) {
        working_final_len = 0;
        if (i % 2 == 0) { // if i is even intermsum_i
            memcpy(working_final + working_final_len, interm1000_sum_prealloc, i_len);
            working_final_len += i_len;
        }
        else { // else, concatenate password
            memcpy(working_final + working_final_len, psswd, p_len);
            working_final_len += p_len;
        }
        if (i % 3 != 0) { // if not divisible by 3, salt
            memcpy(working_final + working_final_len, salt, s_len);
            working_final_len += s_len;
        }
        if (i % 7 != 0) { // if not divisible by 7, password
            memcpy(working_final + working_final_len, psswd, p_len);
            working_final_len += p_len;
        }
        if (i % 2 == 0) { // if i is even, psswd
            memcpy(working_final + working_final_len, psswd, p_len);
            working_final_len += p_len;
        }
        else { // if i is odd, intermsum_i
            memcpy(working_final + working_final_len, interm1000_sum_prealloc, i_len);
            working_final_len += i_len;
        }
        compute_primitive_md5(working_final, working_final_len, interm1000_sum_prealloc);
        // compute_primitive_md5(working_final, working_final_len, tmptmptmp);
        // memcpy(interm1000_sum_prealloc, tmptmptmp, 16);
    }
    return;
}


char gimme_char(bitset<128> bit_grp) { // 22 groups total
    int to_int = static_cast<int>(bit_grp.to_ulong());
    string crypt_str = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    return crypt_str[to_int];
}


void rearrange(char * finalsum, unsigned sum_len, char* partitioned_stuff) {
    // output magic, then salt, then '$' to separate salt from encrypted section
    // then convert string to binary
    // reordering shenanigans (11 4 10 5 3 9 15 2 8 14 1 7 13 0 6 12)
    // int byte_seq[16] = {11, 4, 10, 5, 3, 9, 15, 2, 8, 14, 1, 7, 13, 0, 6, 12};
    int byte_seq[16] = {12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11}; // totally not arbitrary
    char *new_order = new char[sum_len];
    for(unsigned i = 0; i < sum_len; ++i) {
        new_order[i] = finalsum[byte_seq[i]];
    }
    // partition into groups of 6 bits (22 groups total)
    // beginning with the least significant (rightmost)
    // NOTE: the link says no additional padding, but we're electing to ignore that

    // new_order_bin >>= 2;

    for(unsigned i = 0; i < 20; i += 4) {
        partitioned_stuff[i] = gimme_char(new_order[0] & 0x3f);
        partitioned_stuff[i+1] = gimme_char(((new_order[0] & 0xc0) >> 6) | ((new_order[1] & 0xf) << 2));
        partitioned_stuff[i+2] = gimme_char(((new_order[1] & 0xf0) >> 4) | ((new_order[2] & 0x3) << 4));
        partitioned_stuff[i+3] = gimme_char((new_order[2] & 0xfc) >> 2);
        new_order = new_order + 3;
    }

    partitioned_stuff[21] = gimme_char((new_order[0] & 0xc0) >> 6);
    partitioned_stuff[20] = gimme_char((new_order[0] & 0x3f));

    partitioned_stuff[22] = '\0';
    return;
}

