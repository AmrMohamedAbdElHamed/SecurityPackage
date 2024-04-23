using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        #region Tables
        // first IP for the input
        int[] IP = {58,50,42,34,26,18,10,2,
                    60,52,44,36,28,20,12,4,
                    62,54,46,38,30,22,14,6,
                    64,56,48,40,32,24,16,8,
                    57,49,41,33,25,17,9,1,
                    59,51,43,35,27,19,11,3,
                    61,53,45,37,29,21,13,5,
                    63,55,47,39,31,23,15,7};
        // Inverse Initial Permutation (IP–1)
        int[] IP_inverse = {40, 8, 48, 16, 56, 24, 64, 32,
                            39, 7, 47, 15, 55, 23, 63, 31,
                            38, 6, 46, 14, 54, 22, 62, 30,
                            37, 5, 45, 13, 53, 21, 61, 29,
                            36, 4, 44, 12, 52, 20, 60, 28,
                            35, 3, 43, 11, 51, 19, 59, 27,
                            34, 2, 42, 10, 50, 18, 58, 26,
                            33, 1, 41, 9,  49, 17, 57, 25};
        // Expansion Permutation (E)
        int[] E = { 32, 1 ,2 ,3, 4, 5,
                    4 , 5 ,6, 7, 8, 9,
                    8 , 9 , 10, 11, 12, 13,
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32, 1};
        //  Permutation Function (P)
        int[] P = {16,  7, 20, 21, 29, 12, 28, 17,
                    1, 15, 23, 26,  5, 18, 31, 10,
                    2,  8, 24, 14, 32, 27,  3,  9,
                   19, 13, 30,  6, 22, 11,  4, 25};
        // S_Boxes
        int[] S1 = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 };

        int[] S2 = {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 };

        int[] S3 = {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 };

        int[] S4 = {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 };

        int[] S5 = {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 };

        int[] S6 = {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 };

        int[] S7 = {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 };

        int[] S8 = {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11};

        // Permuted Choice One (PC-1)
        int[] PC_1_C = {57, 49, 41, 33, 25, 17, 9,
                        1, 58, 50, 42, 34, 26, 18,
                        10, 2, 59, 51, 43, 35, 27,
                        19, 11, 3, 60, 52, 44, 36 };
        int[] PC_1_D = {63, 55, 47, 39, 31, 23, 15,
                        7, 62, 54, 46, 38, 30, 22,
                        14, 6, 61, 53, 45, 37, 29,
                        21, 13, 5, 28, 20, 12, 4 };
        // Permuted Choice Two (PC-2)
        int[] PC_2 = {14, 17, 11, 24, 1, 5, 3, 28,
                      15, 6, 21, 10, 23, 19, 12, 4,
                      26, 8, 16, 7, 27, 20, 13, 2,
                      41, 52, 31, 37, 47, 55, 30, 40,
                      51, 45, 33, 48, 44, 49, 39, 56,
                      34, 53, 46, 42, 50, 36, 29, 32 };
        // Schedule of Left Shifts
        int[] Schedule_of_left_shifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        #endregion
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            //convert plainText and key to a 64 block
            int[] b1 = convert_to_64block(cipherText);
            int[] key_64block = convert_to_64block(key);

            //input the plain text to IP
            int[] b1_ip = new int[64];
            for (int i = 0; i < 64; i++)
            {
                b1_ip[i] = b1[IP[i] - 1];
            }
            // Get key of all rounds
            List<int[]> keys = new List<int[]>();
            // GET C and D  ,key PC_1
            int[] C = Get_C_D(key_64block, 'C');
            int[] D = Get_C_D(key_64block, 'D');
            for (int i = 0; i < 16; i++)
            {
                // Shift the C and D
                C = Shift_left(C, Schedule_of_left_shifts[i]);
                D = Shift_left(D, Schedule_of_left_shifts[i]);

                // Permuted Choice Two (PC-2)
                int[] key_temp = Apply_PC_2(C, D);
                keys.Add(key_temp);
            }

            // for the 16 ROUNDS
            for (int round = 0; round < 16; round++)
            {
                // Round
                b1_ip = Round(b1_ip, keys[15 - round]);
            }
            // 32 bit swap
            int[] left_b = new int[32];
            int[] right_b = new int[32];
            for (int i = 0; i < 32; i++)
            {
                left_b[i] = b1_ip[i];
                right_b[i] = b1_ip[i + 32];
            }
            for (int i = 0; i < 32; i++)
            {
                b1_ip[i] = right_b[i];
                b1_ip[i + 32] = left_b[i];
            }
            // inverse initial permutation
            int[] plain = new int[64];
            for (int i = 0; i < 64; i++)
            {
                plain[i] = b1_ip[IP_inverse[i] - 1];
            }
            // convert to hex in string
            string plain_hex = "0x";
            for (int i = 0; i < 16; i++)
            {
                plain_hex += Convert.ToString(Convert.ToInt64($"{plain[(i * 4)]}{plain[(i * 4) + 1]}{plain[(i * 4) + 2]}{plain[(i * 4) + 3]}", 2), 16);

            }
            return plain_hex;
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            //convert plainText and key to a 64 block
            int[] b1 = convert_to_64block(plainText);
            int[] key_64block = convert_to_64block(key);

            //input the plain text to IP
            int[] b1_ip = new int[64];
            for (int i = 0; i < 64; i++)
            {
                b1_ip[i] = b1[IP[i]-1];
            }

            // GET C and D  ,key PC_1
            int[] C = Get_C_D(key_64block,'C');
            int[] D = Get_C_D(key_64block, 'D');

            // for the 16 ROUNDS
            for (int round = 0; round < 16; round++)
            {
                // Shift the C and D
                C = Shift_left(C, Schedule_of_left_shifts[round]);
                D = Shift_left(D, Schedule_of_left_shifts[round]);

                // Permuted Choice Two (PC-2)
                int[] PC_2 = Apply_PC_2(C, D);

                // Round
                b1_ip = Round(b1_ip, PC_2);
            }
            // 32 bit swap
            int[] left_b = new int[32];
            int[] right_b = new int[32];
            for (int i = 0; i < 32; i++)
            {
                left_b[i] = b1_ip[i];
                right_b[i] = b1_ip[i + 32];
            }
            for (int i = 0; i < 32; i++)
            {
                b1_ip[i] = right_b[i];
                b1_ip[i + 32] = left_b[i];
            }
            // inverse initial permutation
            int[] cipher = new int[64];
            for (int i = 0; i < 64; i++)
            {
                cipher[i] = b1_ip[IP_inverse[i] - 1];
            }
            // convert to hex in string
            string cipher_hex = "0x";
            for (int i = 0; i < 16; i++)
            {
                cipher_hex += Convert.ToString(Convert.ToInt64($"{cipher[(i*4)]}{cipher[(i * 4) + 1]}{cipher[(i * 4) + 2]}{cipher[(i * 4) + 3]}",2), 16);

            }
            return cipher_hex;
        }
        public int[] convert_to_64block(string S)
        {
            string new_S = S.Remove(0, 2);
            string binaryString = Convert.ToString(Convert.ToInt64(new_S, 16), 2);
            int zeros = 64 - binaryString.Length;
            int[] b1 = new int[64];
            for (int i = zeros; i < 64; i++)
            {
                if (binaryString[i - zeros] == '1')
                    b1[i] = 1;
                else
                    b1[i] = 0;
            }
            return b1;
        }
        public int[] Get_C_D(int[] key_64block, char c)
        {
            if(c == 'C')
            {
                int[] C = new int[28];
                for (int i = 0; i < 28; i++)
                {
                    C[i] = key_64block[PC_1_C[i] - 1];
                    
                }
                return C;
            }
            else if(c == 'D')
            {
                int[] D = new int[28];
                for (int i = 0; i < 28; i++)
                {
                    D[i] = key_64block[PC_1_D[i] - 1];
                }
                return D;
            }
            return null;
        }
        public int[] Shift_left(int[] T ,int shift)
        {
            int[] ret = new int[28];
            if (shift == 1)
            {
                int temp = T[0];
                for (int i = 0; i < 27; i++)
                {
                    ret[i] = T[i + 1];
                }
                ret[27] = temp;
            }
            else if (shift == 2)
            {
                int temp = T[0];
                int temp2 = T[1];
                for (int i = 0; i < 26; i++)
                {
                    ret[i] = T[i + 2];
                }
                ret[26] = temp;
                ret[27] = temp2;
            }
            else
                throw new Exception("wrong shift number: "+shift);
            return ret;
        }
        public int[] Apply_PC_2(int[] C, int[] D)
        {
            int[] C_D = new int[56];
            int[] ret = new int[48];
            for (int i = 0; i < 28; i++)
            {
                C_D[i] = C[i];
                C_D[i+28] = D[i];
            }
            for (int i = 0; i < 48; i++)
            {
                ret[i] = C_D[PC_2[i] - 1];
            }
            return ret;
        }
        public int[] Round(int[] b1, int[] key_pc2)
        {
            int[] result = new int[64];
            //split b1 to left and right
            int[] left_b = new int[32];
            int[] right_b = new int[32];
            for (int i = 0; i < 32; i++)
            {
                left_b[i] = b1[i]; 
                right_b[i] = b1[i + 32]; 
            }
            // Expansion premutation for the right side
            int[] right_exp = new int[48];
            for (int i = 0; i < 48; i++)
            {
                right_exp[i] = right_b[E[i] - 1];
            }
            // XOR right_exp with key
            int[] xor_result = new int[48];
            for (int i = 0; i < 48; i++)
            {
                xor_result[i] = right_exp[i] ^ key_pc2[i];
            }
            // S_box
            int[] S_box_result = new int[32];
            for (int S = 0, i = 0; S < 8; S++)
            {
                if(i + 6 <= 48)
                {
                    int row = Convert.ToInt32($"{xor_result[i]}{xor_result[i + 5]}", 2);
                    int column = Convert.ToInt32($"{xor_result[i + 1]}{xor_result[i + 2]}{xor_result[i + 3]}{xor_result[i + 4]}", 2);
                    string num = Convert.ToString(S_box(row, column, S),2);
                    int zero_to_add = 4 - num.Length;
                    for (int z = 0; z < zero_to_add; z++)
                    {
                        num = '0' + num;
                    }
                    for (int j = 0; j < 4; j++)
                    {
                        if (num[j] == '1')
                            S_box_result[(S * 4) + j] = 1;
                        else if (num[j] == '0')
                            S_box_result[(S * 4) + j] = 0;
                    }
                }
                i += 6;
            }
            // P premutation
            int[] premutation_result = new int[32];
            for (int i = 0; i < 32; i++)
            {
                premutation_result[i] = S_box_result[P[i] - 1];
            }
            // XOR with left side
            int[] xor_result2 = new int[32];
            for (int i = 0; i < 32; i++)
            {
                xor_result2[i] = left_b[i] ^ premutation_result[i];
            }
            // left side = old right side and xor_result2 is the new right side
            for (int i = 0; i < 32; i++)
            {
                result[i] = right_b[i];
                result[i + 32] = xor_result2[i];
            }

            return result;
        }
        public int S_box(int row, int column,int S)
        {
            switch (S)
            {
                case 0:
                    return S1[(row*16) + column];
                case 1:
                    return S2[(row * 16) + column];
                case 2:
                    return S3[(row * 16) + column];
                case 3:
                    return S4[(row * 16) + column];
                case 4:
                    return S5[(row * 16) + column];
                case 5:
                    return S6[(row * 16) + column];
                case 6:
                    return S7[(row * 16) + column];
                case 7:
                    return S8[(row * 16) + column];
                default:
                    return -1;
            }
        }
    }
}
