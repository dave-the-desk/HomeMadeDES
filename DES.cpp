#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <sstream>
#include <bitset>

using namespace std;

string PC1(string prePC1);
string PC2(string c_half, string d_half);
string SubKeys(int keyIndex, string key);
string IP(string preIP);
string E_Bit_Selection(string preRight);
string S_Table_Conversion(string PreS);
string P(string preP);
string IPInverse(string preInverse);
string Binary_Conversion(const string &Hex);
string Binary_Shifter(string PreShifted, int shiftIndex);
string TableEncoding(int table[], string plaintext);
string XOR(string a, string b);
string Hex_Conversion(const string &binary);
string trim(const string& str);

int main(int argc, char* argv[]) {

    /*-----------------------------------------------------------
    ----------------Importing The Input File --------------------
    ------------------------------------------------------------*/

    //if not formatted right in terminal, it will throw an error
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <input_file> <output_file>\n";
        return 1;
    }

    string input_file = argv[1];
    string output_file = argv[2];

    //error thrown if file can't be opened
    ifstream infile(input_file);
    if (!infile) {
        cerr << "Error: Cannot open input file " << input_file << "\n";
        return 1;
    }

    //get string values for key, cipher or plain text and whether to encrypt or decrypt
    string input_key;
    string data_block;
    string operation;

    string line;
    while (getline(infile, line)) {
        // Parse the data block
        if (line.find("data_block:") != std::string::npos) {
            data_block = trim(line.substr(line.find(":") + 1)); // Extract the value after ':'
        }
        // Parse the key
        else if (line.find("key:") != std::string::npos) {
            input_key = trim(line.substr(line.find(":") + 1));
        }
        // Parse the operation (encryption or decryption)
        else if (line.find("operation:") != std::string::npos) {
            operation = trim(line.substr(line.find(":") + 1));
        }
    }

    //open output file
    ofstream outfile(output_file);
    if (!outfile) {
        cerr << "Error: Cannot open output file " << output_file << "\n";
        return 1;
    }

    /*-----------------ENCRYPTION-----------------------*/
    if (operation == "encryption") {
        // Create 16 Subkeys
        string key = Binary_Conversion(input_key);
        string plaintext = Binary_Conversion(data_block);

        /*-----------------------------------------------------------
        ----------------Key Encoding ----------------------------
        ------------------------------------------------------------*/

        // PC1 to the key
        string key_plus = PC1(key);

        // Create 16 subkey halves, c and d, into two different arrays
        string C[17];
        string D[17];

        if (key_plus.length() % 2 == 0) {
            string tempC = key_plus.substr(0, 28);
            string tempD = key_plus.substr(28, 28);

            for (int i = 0; i <= 16; i++) {
                if (i == 0) {
                    C[i] = tempC;
                    D[i] = tempD;
                } else {
                    C[i] = SubKeys(i, C[i - 1]);
                    D[i] = SubKeys(i, D[i - 1]);
                }
                outfile << "C" << i << "=" << C[i] << endl;
                outfile << "D" << i << "=" << D[i] << endl;
            }
            outfile << endl;
        }

        // Apply PC2 to the 16 separate keys
        string SubKeys[17];
        for (int i = 1; i <= 16; i++) {
            SubKeys[i] = PC2(C[i], D[i]);
            outfile << "K" << i << "=" << SubKeys[i] << endl;
        }
        outfile << endl;
        // We now have 16 subkeys

        /*-----------------------------------------------------------
        ----------------Apply Key To Plaintext ----------------------
        ------------------------------------------------------------*/

        // Take an initial permutation (IP) of the data
        string post_IP_PlainText = IP(plaintext);

        // Split message in half
        if (post_IP_PlainText.length() % 2 == 0) {
            string tempL = post_IP_PlainText.substr(0, 32);
            string tempR = post_IP_PlainText.substr(32, 32);

            string L[17];
            string R[17];

            for (int i = 0; i <= 16; i++) {
                if (i == 0) {
                    L[i] = tempL;
                    R[i] = tempR;
                } else {
                    L[i] = R[i - 1];
                    R[i] = XOR(L[i - 1], P(S_Table_Conversion(XOR(SubKeys[i], E_Bit_Selection(R[i - 1])))));
                }
                outfile << "L" << i << "=" << L[i] << endl;
                outfile << "R" << i << "=" << R[i] << endl;
            }
            outfile << endl;

            outfile << "Result=" << Hex_Conversion(IPInverse(R[16] + L[16]));
        }

        return 0; // return
    /*----------------DECODING---------------------*/
    } else if (operation == "decryption") {
        string key = Binary_Conversion(input_key);
        string ciphertext = Binary_Conversion(data_block);

        string key_plus = PC1(key);

        string C[17];
        string D[17];
        /*-----------------------------------------------------------
        ----------------Key Decoding --------------------------------
        ------------------------------------------------------------*/
    if (key_plus.length() % 2 == 0) {
            string tempC = key_plus.substr(0, 28);
            string tempD = key_plus.substr(28, 28);

            for (int i = 0; i <= 16; i++) {
                if (i == 0) {
                    C[i] = tempC;
                    D[i] = tempD;
                } else {
                    C[i] = SubKeys(i, C[i - 1]);
                    D[i] = SubKeys(i, D[i - 1]);
                }
                outfile << "C" << i << "=" << C[i] << endl;
                outfile << "D" << i << "=" << D[i] << endl;
            }
            outfile << endl;
        }

            string SubKeys[17];
                for (int i = 1; i <= 16; i++) {
                SubKeys[i] = PC2(C[i], D[i]);
            }

            // Reverse the SubKeys array for decryption
            
            for (int i = 1; i <= 8; i++) {
                string temp = SubKeys[i];
                SubKeys[i] = SubKeys[17 - i];
                SubKeys[17 - i] = temp;
            }

            for (int i = 1; i <= 16; i++) {
                outfile << "K" << i << "=" << SubKeys[i] << endl;
            }

            outfile << endl;


        /*-----------------------------------------------------------
        ----------------Apply Key To Ciphertext ----------------------
        ------------------------------------------------------------*/

        string post_IP_CipherText = IP(ciphertext);

        if(post_IP_CipherText.length() % 2 == 0){
            string L[17], R[17];
            string tempL = post_IP_CipherText.substr(0, 32);
            string tempR = post_IP_CipherText.substr(32, 32);

            for (int i = 0; i <= 16; i++) {
                if(i == 0){
                    L[i] = tempL;
                    R[i] = tempR;
                }else{
                    L[i] = R[i - 1];
                    R[i] = XOR(L[i - 1], P(S_Table_Conversion(XOR(SubKeys[i], E_Bit_Selection(R[i - 1])))));
                }
                outfile << "L" << i << "=" << L[i] << endl;
                outfile << "R" << i << "=" << R[i] << endl;
            }

            outfile << endl;

            string final_block = R[16] + L[16];
            string plaintext_in_binary = IPInverse(final_block);

            outfile << "Result=" << Hex_Conversion(plaintext_in_binary);
        }

        
    }

    return 0; // Closing the main() function
}


string Hex_Conversion(const string &binary) {
    bitset<64> bits(binary);
    unsigned long long int_value = bits.to_ullong();

    stringstream ss;
    ss << hex << uppercase << setw(16) << setfill('0') << int_value;  // Always output 16 hex digits

    return ss.str();
}


string Binary_Conversion(const string &Hex){
    stringstream binary;

    for(char hexChar: Hex){
        unsigned int value;
        stringstream stream;
        stream << hex << hexChar;
        stream >> value;

        bitset<4> bits(value);
        binary << bits.to_string();
    }

    return binary.str();
}

string TableEncoding(int table[], string plaintext, int size){
    string ciphertext = "";
    for(int i = 0; i < size; i++){
        ciphertext = ciphertext + plaintext[table[i] - 1];
    }
    return ciphertext;
}


string PC1(string prePC1){
    int pc_1[56] = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
    return TableEncoding(pc_1, prePC1, 56);

}

string Binary_Shifter(string PreShifted, int shiftIndex) {

    // Perform circular left shift
    string shifted = PreShifted.substr(shiftIndex) + PreShifted.substr(0, shiftIndex);

    // Ensure the shifted string has the correct number of bits
    return shifted;
}


string SubKeys(int keyIndex, string key){
    switch (keyIndex) {
    case 3: case 4: case 5: case 6: case 7: case 8:
    case 10: case 11: case 12: case 13: case 14: case 15:
        return Binary_Shifter(key, 2);
        break;
    default:
        return Binary_Shifter(key, 1);
    }

    
}

string PC2(string c_half, string d_half){
    string prePC2 = c_half + d_half;
    int pc_2[48] = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
    return TableEncoding(pc_2, prePC2, 48);
}

string IP(string preIP){
    int ip[64] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
    return TableEncoding(ip, preIP, 64);
}

string E_Bit_Selection(string preRight){
    int e_bit[48] = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
    return TableEncoding(e_bit, preRight, 48);
}

string XOR(string a, string b) {
    // Adjust to the same length by padding the shorter one with leading zeros
    while (a.length() < b.length()) a = '0' + a;
    while (b.length() < a.length()) b = '0' + b;

    // Use bitsets of the appropriate size
    bitset<64> x(a);  // Adjust size if needed
    bitset<64> y(b);  // Adjust size if needed

    bitset<64> result = x ^ y;

    return result.to_string().substr(64 - a.length());  // Ensure output matches original size
}


string S_Table_Conversion(string PreS){
   
    string B[8];
    for(int i = 0; i < 8; i++){
        B[i] = PreS.substr((i * 6), 6);
    }
    

    int S_1[4][16] = {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    };

    int S_2[4][16] = {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, 
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, 
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, 
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}

    };

    int S_3[4][16] = {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, 
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    };

    int S_4[4][16] = {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    };
    int S_5[4][16] = {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    };

    int S_6[4][16] = {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    };

    int S_7[4][16] = {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    };

    int S_8[4][16] = {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    };

    int (*S_boxes[8])[16] = {S_1, S_2, S_3, S_4, S_5, S_6, S_7, S_8};

    string r, c;
    
    int row, column;

    string result = "";


    for(int i = 0; i < 8; i++){
        r = (B[i].substr(0,1) + B[i].substr(5,1));
        c = B[i].substr(1, 4);

        row = stoi(r, nullptr, 2);
        column = stoi(c, nullptr, 2);

        result = result + bitset<4>(S_boxes[i][row][column]).to_string();
    }

    return result;

}

string P(string preP){
    int p[32] = {16,  7, 20, 21,
                29, 12, 28, 17,
                1, 15, 23, 26,
                5, 18, 31, 10,
                2,  8, 24, 14,
                32, 27,  3,  9,
                19, 13, 30,  6,
                22, 11,  4, 25 };
    
    return TableEncoding(p, preP, 32);  
}

string IPInverse(string preInverse){
    int ip_inverse[64] = {40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25};

    return TableEncoding(ip_inverse, preInverse, 64);
}

string trim(const string& str) {
    size_t first = str.find_first_not_of(' ');
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}