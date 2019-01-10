#include <stdlib>
#include <bitset>
#include <to_ulong>

using namespace std;

string compute_altsum(string salt, string passwd); // needed to compute intermediate_0 sum
string compute_intermsum(string psswd, string magic, string salt, string altsum); // intermediate_0 sum
string interm_1000(string psswd, string salt, string intermsum); // extends to intermsum to intermediate_1000 sum
bitset<128> str_to_bin(string tmp); // for the final printing
string md5_crypthash(string passwd, string salt, string magic, string finalsum);

int main() {
    // compute alternate sum
    // compute intermediate sum
    // remaining calculations to extend intermsum to interm_1000
    return 0;
}


// compute alternate sum
string compute_altsum(string salt, string passwd) {
    return altsum; // replace altsum with md5(psswd + salt + psswd); TODO: look into the library Alex sent and get rid of the overhead of this function
}


// compute intermediate sum (Intermediate_0)
string compute_intermsum(string psswd, string magic, string salt, string altsum) {
    //concatenate the inputs; altsum is repeated as necessaryi
    // For each bit in length(password), from low to high and stopping after the most significant set bit such that
    // if (!bit.set()) {
    //  intermsum.append(a NUL byte)
    
    //}
    // else {
    //      intermsum.append(first byte of the password)
    
    // }

    return intermsum;
}


// remaining calculations (Intermediate_0 extended to Intermediate_1000)
string interm_1000(string psswd, string salt, string intermsum) {
    string working_final;
    string tmp_intermsum = intermsum;
    for (unsigned i = 0; i < 1000; ++i) {
        working_final = "";
        if (i % 2 == 0) { // if i is even intermsum_i
            working_final.append(tmp_intermsum);
        }
        else { // else, concatenate password
            working_final.append(psswd);
        }
        if (i % 3 != 0) { // if not divisible by 3, salt
            working_final.append(salt);
        }
        if (i % 7 != 0) { // if not divisible by 7, password
            working_final.append(psswd);
        }
        if (i % 2 == 0) { // if i is even, psswd
            working_final.append(psswd);
        }
        else { // if i is odd, intermsum_i
            working_final.append(tmp_intermsum);
        }
        tmp_intermsum = md5(working_final);
    }
    return tmp_intermsum; // actually the final thing
}

// HEREEEEEEEEEE
string md5_crypthash(string psswd, string salt, string magic, string finalsum) {
    // output magic, then salt, then '$' to separate salt from encrypted section
    string tmp = magic.append(salt).append('$');
    // then convert string to binary
    bitset<128> much_binary (finalsum.c_str());
    // reordering shenanigans (11 4 10 5 3 9 15 2 8 14 1 7 13 0 6 12)
    int byte_seq[16] = {11, 4, 10, 5, 3, 9, 15, 2, 8, 14, 1, 7, 13, 0, 6, 12}; // totally not arbitrary
    bitset<128> new_WORLD_order; 
    for (unsigned i = 0; i < 16; ++i) { // find the bytes of totally not arbitrary order in the not arbitrary order
        // reorder stoof
        ith_start = byte_seq[i] * 8;
        ith_end = ith_start + 7;
        jth_start = i * 8;
        jth_end = jth_start + 7; // index of bits
        // identifying the bits in the byte in question
        for (unsigned j = jth_start; j <= jth_end; ++j) {
            new_WORLD_order[j] = much_binary[j];
        }
    }
    // partition into groups of 6 bits (22 groups total)
    //beginning with the least significant
    //NOTE: the link says no additional padding, but we're electing to ignore that
    string partitioned_stuff;
    for (unsigned i = 127; i >= 0; i = i - 6) {
        if (i > 128) { // to catch the BIG number :^)
            break;
        }
        bitset<6> tmp_bits;
        for (unsigned j = 6; j >= 6; ++j) {
            if (j > 7) { // another BIG one :^')
                break;
            }
            tmp[6 - j] = new_WORLD_order[i - j];
        }
        // convert to char base64
        partitioned_stuff = partitioned_stuff.append(gimme_char(tmp_bits));
    }
    // output corresponding base64 character with said grop of 6 bits
    
    return tmp.append(partitioned_stuff);
}


string gimme_char(bitset<6> bit_grp) { // 22 groups total
    int to_int = static_cast<int>(bit_grp.to_ulong());
    string crypt_str = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    char crypt_arr[crypt_str.size()+1];
    strcpy(crypt_arr, crypt_str.c_str());
    return crypt_arr[to_int]; // NOTE / TODO: check type later; currently a str of length 1
}

