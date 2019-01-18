#include <openssl/md5.h>
#include <cstdlib>
#include <bitset>
#include <iostream>
#include <cstring>
#include <iomanip>
#include <thread>
#include <ctime>
using namespace std;

void compute_intermsum(char* psswd, unsigned p_len, char* magic, unsigned m_len, char* salt, unsigned s_len, char* altsum, unsigned a_len, char* intermsum_prealloc); // intermediate_0 sum
void interm_1000(char* psswd, unsigned p_len, char* salt, unsigned s_len, char* intermsum, unsigned i_len, char* interm1000_sum_prealloc); // extends to intermsum to intermediate_1000 sum
void rearrange(char* finalsum, unsigned sum_len, char* partitioned_stuff);
void compute_primitive_md5(char* input, unsigned in_len, char* altsum_prealloc); //return the "primitive" md5 hash of a string
void print_char_hex(char* to_print, unsigned len);
void print_char_reg(char* to_print, unsigned len);
bool check_pass(char* psswd);
bool get_next_pass(char* pass, char start_at, bool direction);
void check_block(char* start, char* end, bool direction);
// List<char> god_list = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
// Map<char, > god_map = {{'a', 'a'}, {'b', 'b'}, {'c', 'c'}, {'d', 'd'}, {'e', 'e'}, {'f', 'f'}, {'g', 'g'}, {'h', 'h'}, {'i', 'i'}, {'j', 'j'}, {'k', 'k'}, {'l', 'l'}, {'m', 'm'}, 
// {'n', 'n'}, {'o', 'o'}, {'p', 'p'}, {'q', 'q'}, {'r', 'r'}, {'s', 's'}, {'t', 't'}, {'u', 'u'}, {'v', 'v'}, {'w', 'w'}, {'x', 'x'}, {'y', 'y'}, {'z', 'z'}}


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
    char salt[9] = "hfT7jp2q";
    char hash[23] = "v8XH/MrpaYdagdMgM4yKc."; //THIS IS THE REAL HASH
    //char hash[23] =    "O53e58A82lSBz1tJeJRfY/";
    char magic[4] = "$1$";
    // compute alternate sum
    char input[21];
    strcpy(input, psswd);
    strcat(input, salt);
    strcat(input, psswd);
    
    unsigned input_size = 20; // definitely not including the null character at the end
    char altsum_prealloc[16];
    compute_primitive_md5(input, input_size, altsum_prealloc); // computes the altsum

    // compute intermediate sum
    unsigned psswd_size = 6; 
    unsigned magic_size = 3; 
    unsigned salt_size = 8; 
    unsigned altsum_size = 16; 
    char intermsum_prealloc[16];  // oNLY WORKS ON PASSWORD SIZES OF 16
    compute_intermsum(psswd, psswd_size, magic, magic_size, salt, salt_size, altsum_prealloc, altsum_size, intermsum_prealloc);

    // remaining calculations to extend intermsum to interm_1000
    char interm1000_sum_prealloc[16];
    unsigned intermsum_size = 16;
    interm_1000(psswd, psswd_size, salt, salt_size, intermsum_prealloc, intermsum_size, interm1000_sum_prealloc);

    // rearrange/hash the bytes of the interm_1000
    char partitioned_stuff[23];
    unsigned interm1000_size = 16;
    rearrange(interm1000_sum_prealloc, interm1000_size, partitioned_stuff);

    if(strncmp(partitioned_stuff, hash, 22) == 0) {
        return true;
    }
    return false;
}

// "direction = true" means towqard z
bool get_next_pass(char* pass, char * end_at, bool direction) { // return true if pass contains a valid password when returning i.e. when no more passwords to compute, returns false
    for (unsigned i = 5; i >= 0 & i < 6; --i) {
        if(direction) {
            if (pass[i] + 1 == '{') {
                pass[i] = 'a';
            } else{
                pass[i]++;
                break; 
            }
        } else {
            if(pass[i] - 1 == '`') {
                pass[i] = 'z';
            } else {
                pass[i]--;
                break;
            }
        } 
    }
    // do i call again?
    //compare pass to end at
    if (memcmp(pass, end_at, 6) == 0) {
        return false;
    }
    return true;
}

// "direction = true" means towqrds z
void check_block(char* start, char* end, bool direction) { // THREAD THIS
    cout << "Thread made?" << endl;
    do{
        if(check_pass(start)) {
            printf("YOU FOUND IT: %s\n", start);
            exit(0);
        }
    } while (get_next_pass(start, end, direction));
        if(check_pass(start)) {
        printf("YOU FOUND IT: %s\n", start);
        exit(0);
    }
}


int main(int argc, char** argv) { // TODO: 
    // char test[7] = "xyzabc";
    // char end_test[7] = "zccdef";
    
    char begin_1[7] = "zzzzzz"; // TESTING BEGIN
    char end_1[7] = "zzzaaa";
    char begin_2[7] = "zzyzzz";
    char end_2[7] = "zzyaaa";
    char begin_3[7] = "zzxzzz";
    char end_3[7] = "zzxaaa";
    char begin_4[7] = "zzwzzz";
    char end_4[7] = "zzwaaa";
    char begin_5[7] = "zzvzzz";
    char end_5[7] = "zzvaaa";
    char begin_6[7] = "zzuzzz";
    char end_6[7] = "zzuaaa";
    char begin_7[7] = "zztzzz";
    char end_7[7] = "zztaaa";
    char begin_8[7] = "zzszzz";
    char end_8[7] = "zzsaaa";
    char begin_9[7] = "zzrzzz";
    char end_9[7] = "zzraaa";
    
    double duration;
    time_t start;

    start = clock();
    thread t1(check_block, begin_1, end_1, 0);
    // thread t2(check_block, begin_2, end_2, 0);
    // thread t3(check_block, begin_3, end_3, 0);
    // thread t4(check_block, begin_4, end_4, 0);
    // thread t5(check_block, begin_5, end_5, 0);
    // thread t6(check_block, begin_6, end_6, 0);
    // thread t7(check_block, begin_7, end_7, 0);
    // thread t8(check_block, begin_8, end_8, 0);
    // thread t9(check_block, begin_9, end_9, 0);
    t1.join();
    // t2.join();
    // t3.join();
    // t4.join();
    // t5.join();
    // t6.join();
    // t7.join();
    // t8.join();
    // t9.join();
    duration = (clock() - start ) / (double) CLOCKS_PER_SEC;
    cout << "time: " << duration << ": " << (double)(26*26*26 / duration) << " passwords per sec" << endl;



    cout << "DONE" << endl; // TESTING END

    return 0;
}

// tell each thread where to start, which direction to go in, and how many passwords to skip
void compute_primitive_md5(char* input, unsigned in_len, char* digest) {
    // char digest[16];   //allocate 16 bytes for result, or "digest"
    MD5_CTX* context = new MD5_CTX();
    MD5_Init(context);
    MD5_Update(context, (unsigned char*)(input), in_len);
    MD5_Final((unsigned char*)(digest), context);
    delete context;
    // MD5((unsigned char*)(input), in_len, (unsigned char*)(digest));    //compute the md5 (which is also the altsum)
    return;
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
        if ((i & 0x1) == 0) { // if i is even intermsum_i
            memcpy(working_final + working_final_len, interm1000_sum_prealloc, i_len);
            working_final_len += i_len;
        }
        else { // else, concatenate password
            memcpy(working_final + working_final_len, psswd, p_len);
            working_final_len += p_len;
        }
        if ((i >= 3 ? i % 3 : i) != 0) { // if not divisible by 3, salt
            memcpy(working_final + working_final_len, salt, s_len);
            working_final_len += s_len;
        }
        //if (i % 7 != 0) { // if not divisible by 7, password
        if((i >= 7 ? i % 7 : i) != 0) { // FASSSSSTTTTTT
            memcpy(working_final + working_final_len, psswd, p_len);
            working_final_len += p_len;
        }
        if ((i & 0x1) == 0) { // if i is even, psswd
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
    // reordering shenanigans
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
        new_order += 3;
    }
    partitioned_stuff[21] = gimme_char((new_order[0] & 0xc0) >> 6);
    partitioned_stuff[20] = gimme_char((new_order[0] & 0x3f));
    partitioned_stuff[22] = '\0';
    new_order -= 15;
    delete [] new_order;
    return;
}

