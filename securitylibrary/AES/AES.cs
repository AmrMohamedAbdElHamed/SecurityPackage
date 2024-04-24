using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            #region convert text to matrix


            string hexValue = cipherText.Substring(2);
            int[] cipherArray = Enumerable.Range(0, hexValue.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToInt32(hexValue.Substring(x, 2), 16))
                             .ToArray();

            hexValue = key.Substring(2);
            int[] keyArray = Enumerable.Range(0, hexValue.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToInt32(hexValue.Substring(x, 2), 16))
                             .ToArray();
            int[,] ciphermatrix = new int[4, 4];
            int[,] keymatrix = new int[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int index = j * 4 + i;

                    ciphermatrix[i, j] = cipherArray[index];
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int index = j * 4 + i;

                    keymatrix[i, j] = keyArray[index];
                }
            }
            #endregion
            List<int[,]> keys = new List<int[,]>();
            keys.Add(keymatrix);
            for (int i = 0; i < 10; i++)
            {
                keys.Add(KeySchedule(keys[i], i));
            }

            ciphermatrix = AddRoundKey(ciphermatrix, keys.Last());

            for (int i = 9; i > 0; i--)
            {
                ciphermatrix = ShiftRows(ciphermatrix,true);
                ciphermatrix = INVSubints(ciphermatrix);
                ciphermatrix = AddRoundKey(ciphermatrix, keys[i]);
                ciphermatrix = INVMixColumns(ciphermatrix);

            }
            ciphermatrix = ShiftRows(ciphermatrix,true);
            ciphermatrix = INVSubints(ciphermatrix);
            ciphermatrix = AddRoundKey(ciphermatrix, keys[0]);

            string plainText = "0x";
            string r = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    r = ciphermatrix[j, i].ToString("X");
                    if (r.Length == 1)
                    {
                        r = r.PadLeft(r.Length + 1, '0');
                    }
                    plainText += r;
                }
            }
            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            #region convert text to matrix


            string hexValue = plainText.Substring(2);
            int[] plainArray = Enumerable.Range(0, hexValue.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToInt32(hexValue.Substring(x, 2), 16))
                             .ToArray();

            hexValue = key.Substring(2);
            int[] keyArray = Enumerable.Range(0, hexValue.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToInt32(hexValue.Substring(x, 2), 16))
                             .ToArray();
            int[,] plainmatrix = new int[4, 4];
            int[,] keymatrix = new int[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int index = j * 4 + i;

                    plainmatrix[i, j] = plainArray[index];
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int index = j * 4 + i;

                    keymatrix[i, j] = keyArray[index];
                }
            }
            #endregion

            List<int[,]> list = new List<int[,]>();
            list.Add(keymatrix);
            for (int i = 0; i < 10; i++)
            {
                list.Add(KeySchedule(list[i], i));
            }
            //keymatrix = KeySchedule(keymatrix);

            plainmatrix = AddRoundKey(plainmatrix, keymatrix);

            for (int i = 0; i < 9; i++)
            {
                plainmatrix = Subints(plainmatrix);
                plainmatrix = ShiftRows(plainmatrix,false);
                plainmatrix = MixColumns(plainmatrix);
                plainmatrix = AddRoundKey(plainmatrix, list[i + 1]);

            }
            plainmatrix = Subints(plainmatrix);
            plainmatrix = ShiftRows(plainmatrix,false);
            plainmatrix = AddRoundKey(plainmatrix, list[10]);

            string result = "0x";
            string r = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    r = plainmatrix[j, i].ToString("X");
                    if (r.Length == 1)
                    {
                        r=r.PadLeft(r.Length + 1, '0');
                    }
                    result += r;
                }
            }

            return result;
            //throw new NotImplementedException();
        }


        //Helper Function 
        public int[,] Subints(int[,] plainText)
        {
            int[,] sBox = new int[,]
            {
                { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 },
                { 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0 },
                { 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15 },
                { 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75 },
                { 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84 },
                { 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF },
                { 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8 },
                { 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2 },
                { 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73 },
                { 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB },
                { 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79 },
                { 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08 },
                { 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A },
                { 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E },
                { 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF },
                { 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 }
            };
            int row, col;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string hexValue = plainText[i, j].ToString("X");
                    if (hexValue.Length == 2)
                    {
                        row = Convert.ToInt32(hexValue[0].ToString(), 16);
                        col = Convert.ToInt32(hexValue[1].ToString(), 16);
                    }
                    else
                    {
                        row = 0;
                        col = Convert.ToInt32(hexValue[0].ToString(), 16);
                    }
                    plainText[i, j] = sBox[row, col];
                }
            }
            return plainText;
        }
        public int[,] INVSubints(int[,] plainText)
        {
            int[,] INVsBox = new int[,]
            {
                { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB },
                { 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB },
                { 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E },
                { 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 },
                { 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 },
                { 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 },
                { 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 },
                { 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B },
                { 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 },
                { 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E },
                { 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B },
                { 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 },
                { 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F },
                { 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF },
                { 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 },
                { 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }
            };

            int row, col;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string hexValue = plainText[i, j].ToString("X");
                    if (hexValue.Length == 2)
                    {
                        row = Convert.ToInt32(hexValue[0].ToString(), 16);
                        col = Convert.ToInt32(hexValue[1].ToString(), 16);
                    }
                    else
                    {
                        row = 0;
                        col = Convert.ToInt32(hexValue[0].ToString(), 16);
                    }
                    plainText[i, j] = INVsBox[row, col];
                }
            }
            return plainText;
        }
        public int[,] ShiftRows(int[,] plainText,bool INV)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    if (INV)
                        shiftright(plainText, i);
                    else
                        shiftleft(plainText, i);
                }
            }
            return plainText;
        }
        public int[,] shiftleft(int[,] plainText, int row)
        {
            int temp = plainText[row, 0];
            for (int i = 0; i < 3; i++)
            {
                plainText[row, i] = plainText[row, i + 1];
            }
            plainText[row, 3] = temp;
            return plainText;
        }
        public int[,] shiftright(int[,] plainText, int row)
        {
            int temp = plainText[row, 3];
            for (int i = 3; i > 0; i--)
            {
                plainText[row, i] = plainText[row, i - 1];
            }
            plainText[row, 0] = temp;
            return plainText;
        }
        public int[,] getColumn(int[,] plainText)
        {
            int[,] column = new int[4, 1];

            //shift
            int temp = plainText[0, 3];
            for (int i = 0; i < 3; i++)
            {
                column[i, 0] = plainText[i + 1, 3];
            }
            column[3, 0] = temp;
            //replace from sBox
            int[,] sBox = new int[,]
            {
                { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 },
                { 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0 },
                { 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15 },
                { 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75 },
                { 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84 },
                { 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF },
                { 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8 },
                { 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2 },
                { 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73 },
                { 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB },
                { 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79 },
                { 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08 },
                { 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A },
                { 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E },
                { 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF },
                { 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 }
            };
            int row, col;
            for (int i = 0; i < 4; i++)
            {
                string hexValue = column[i, 0].ToString("X");
                if (hexValue.Length == 2)
                {
                    row = Convert.ToInt32(hexValue[0].ToString(), 16);
                    col = Convert.ToInt32(hexValue[1].ToString(), 16);
                }
                else
                {
                    row = 0;
                    col = Convert.ToInt32(hexValue[0].ToString(), 16);
                }
                column[i, 0] = sBox[row, col];
            }



            return column;
        }
        public int[,] MixColumns(int[,] plainText)
        {
            int[,] m = new int[,] {
                 { 0x02, 0x03, 0x01, 0x01 },
                 { 0x01, 0x02, 0x03, 0x01 },
                 { 0x01, 0x01, 0x02, 0x03 },
                 { 0x03, 0x01, 0x01, 0x02 }
            };

            return MultiplyMatrices(plainText, m,false);
            //throw new NotImplementedException();
        }
        public int[,] INVMixColumns(int[,] plainText)
        {
            int[,] m = new int[,] {
                 { 0x0E, 0x0B, 0x0D, 0x09 },
                 { 0x09, 0x0E, 0x0B, 0x0D },
                 { 0x0D, 0x09, 0x0E, 0x0B },
                 { 0x0B, 0x0D, 0x09, 0x0E }
            };

            return MultiplyMatrices(plainText, m,true);
        }
        public int[,] AddRoundKey(int[,] plainText, int[,] key)
        {


            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plainText[i, j] = plainText[i, j] ^ key[i, j];

                }
            }
            return plainText;
        }
        public int[,] MultiplyMatrices(int[,] matrix1, int[,] matrix2,bool INV)
        {
            int[,] result = new int[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        int a = matrix1[k, i];
                        int b = matrix2[j, k];
                        if(INV)
                            result[j, i] ^= INVGF(a, b);
                        else
                            result[j, i] ^= GF(a, b);
                    }
                }
            }

            return result;
        }
        public int[,] KeySchedule(int[,] key, int index)
        {
            int[,] key_new = new int[4, 4];
            int[,] rcon = new int[,] {
                 { 0x01, 0x02, 0x04, 0x08, 0x10 ,0x20,0x40,0x80,0x1b,0x36 },
                 { 0x00, 0x00, 0x00, 0x00, 0x00 ,0x00,0x00,0x00,0x00,0x00 },
                 { 0x00, 0x00, 0x00, 0x00, 0x00 ,0x00,0x00,0x00,0x00,0x00 },
                 { 0x00, 0x00, 0x00, 0x00, 0x00 ,0x00,0x00,0x00,0x00,0x00 }
            };

            int[,] column = getColumn(key);


            // column xor key xor rcon
            for (int i = 0; i < 4; i++)
            {
                key_new[i, 0] = ((column[i, 0] ^ key[i, 0]) ^ rcon[i, index]);
            }


            for (int j = 1; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    key_new[i, j] = key[i, j] ^ key_new[i, j - 1];
                }

            }





            //for (int j = 1; j < 4; j++)
            //{
            //    for (int i = 0; i < 4; i++)
            //    {
            //        key_new[i, j] = key[i, j] ^ key_new[i, 0];
            //    }
            //}


            //00101011
            //10001010
            //10100001 result

            //10100001
            //00000001
            //10100000 result

            return key_new;
            //throw new NotImplementedException();
        }
        public int GF(int a, int b)
        {
            //87 = 135 
            //6e = 110
            //46 = 70
            //a6 = 166
            //int breakpoint = 0;
            //a = 166;
            //b = 3;
            string r = "";
            if (b == 1)
            {
                return a;
            }
            else if (b == 2)
            {

                string binaryString = Convert.ToString(a, 2);
                binaryString = binaryString.PadLeft(8, '0');
                string p = "00011011";

                string newbinaryString = binaryString.PadRight(binaryString.Length + 1, '0');
                if (newbinaryString[0] == '1')
                {
                    newbinaryString = newbinaryString.Substring(1);
                    char[] result = new char[8];
                    for (int i = 0; i < 8; i++)
                    {
                        result[i] = newbinaryString[i] == p[i] ? '0' : '1';
                    }
                    r = new string(result);
                }
                else
                {
                    newbinaryString = newbinaryString.Substring(1);
                    r = newbinaryString;
                }
            }
            else if (b == 3)
            {
                string binaryString = Convert.ToString(a, 2);
                binaryString = binaryString.PadLeft(8, '0');

                string binaryString3 = binaryString.PadRight(binaryString.Length + 1, '0');
                string binaryString1 = binaryString.PadLeft(binaryString.Length + 1, '0');
                char[] result = new char[9];
                for (int i = 0; i < 9; i++)
                {
                    result[i] = binaryString3[i] == binaryString1[i] ? '0' : '1';
                }
                r = new string(result);
                string p = "00011011";
                if (r[0] == '1')
                {
                    r = r.Substring(1);
                    result = new char[8];
                    //"01100111
                    //"01111100"
                    //"00011011"
                    for (int i = 0; i < 8; i++)
                    {
                        result[i] = r[i] == p[i] ? '0' : '1';
                    }
                    r = new string(result);
                }
                else
                    r = r.Substring(1);

            }
            return Convert.ToInt32(r, 2);

            /*
             ----------------------- test---------------------------



            a = 135;
            string binaryString = Convert.ToString(a, 2);
            binaryString = binaryString.PadLeft(8, '0');
            string p = "00011011";

            string newbinaryString = binaryString.PadRight(binaryString.Length + 1, '0');
            if (newbinaryString[0]=='1')
            {
                newbinaryString=newbinaryString.Substring(1);
                char[] result = new char[8];
                for (int i = 0; i < 8; i++)
                {
                    result[i] = newbinaryString[i] == p[i] ? '0' : '1';
                }
               string r=new string(result);
            }

            ----------------------- test---------------------------
            if (b == 1)
            {
                return a;
            }
            if (b == 2)// we use here  x4+x3+x+1
            {

                string binaryString = Convert.ToString(a, 2);
                binaryString = binaryString.PadLeft(8, '0');
                string p = "00011011";

                binaryString = binaryString.PadRight(binaryString.Length + 1, '0');


                if (binaryString[0] == '1')
                {
                    b = b ^ 27;
                }
            }
            if (b == 3)
            {

            }
            */

        }
        public int INVGF(int a, int b)
        {
            // 0x09 0000 1001
            // 0x0B 0000 1011
            // 0x0D 0000 1101
            // 0x0E 0000 1110

            string r = "";
            if (b == 9) // 0x09 0000 1001
            {
                string binaryString = Convert.ToString(a, 2);
                binaryString = binaryString.PadLeft(8, '0');

                string binaryString_temp = binaryString;

                string binaryString_shift3 = "";
                for (int i = 1; i < 4; i++)
                {
                    binaryString_temp = shift_binary(binaryString_temp);
                    if (i == 3)
                        binaryString_shift3 = binaryString_temp;
                }

                char[] result = new char[8];
                for (int i = 0; i < 8; i++)
                {
                    result[i] = binaryString_shift3[i] == binaryString[i] ? '0' : '1';
                }
                r = new string(result);

                return Convert.ToInt32(r, 2);
            }
            else if (b == 11)// 0x0B 0000 1011
            {
                string binaryString = Convert.ToString(a, 2);
                binaryString = binaryString.PadLeft(8, '0');

                string binaryString_temp = binaryString;

                string binaryString_shift1 = ""; // 0000 0010

                string binaryString_shift3 = ""; // 0000 1000

                for (int i = 1; i < 4; i++)
                {
                    binaryString_temp = shift_binary(binaryString_temp);
                    if (i == 1)
                        binaryString_shift1 = binaryString_temp;
                    if (i == 3)
                        binaryString_shift3 = binaryString_temp;
                }

                char[] result = new char[8];
                for (int i = 0; i < 8; i++)
                {
                    result[i] = binaryString_shift3[i] == binaryString[i] ? '0' : '1';
                    result[i] = result[i] == binaryString_shift1[i] ? '0' : '1';
                }

                r = new string(result);
                return Convert.ToInt32(r, 2);
            }
            else if (b == 13)// 0x0D 0000 1101
            {
                string binaryString = Convert.ToString(a, 2);
                binaryString = binaryString.PadLeft(8, '0');

                string binaryString_temp = binaryString;

                string binaryString_shift2 = ""; // 0000 0100

                string binaryString_shift3 = ""; // 0000 1000

                for (int i = 1; i < 4; i++)
                {
                    binaryString_temp = shift_binary(binaryString_temp);
                    if (i == 2)
                        binaryString_shift2 = binaryString_temp;
                    if (i == 3)
                        binaryString_shift3 = binaryString_temp;
                }
                char[] result = new char[8];
                for (int i = 0; i < 8; i++)
                {
                    result[i] = binaryString_shift3[i] == binaryString[i] ? '0' : '1';
                    result[i] = result[i] == binaryString_shift2[i] ? '0' : '1';
                }
                r = new string(result);
                return Convert.ToInt32(r, 2);

            }
            else if (b == 14) // 0x0E 0000 1110
            {
                string binaryString = Convert.ToString(a, 2);
                binaryString = binaryString.PadLeft(8, '0');

                string binaryString_temp = binaryString;

                string binaryString_shift1 = ""; // 0000 0010

                string binaryString_shift2 = ""; // 0000 0100

                string binaryString_shift3 = ""; // 0000 1000

                for (int i = 1; i < 4; i++)
                {
                    binaryString_temp = shift_binary(binaryString_temp);
                    if (i == 1)
                        binaryString_shift1 = binaryString_temp;
                    if (i == 2)
                        binaryString_shift2 = binaryString_temp;
                    if (i == 3)
                        binaryString_shift3 = binaryString_temp;
                }

                char[] result = new char[8];
                for (int i = 0; i < 8; i++)
                {
                    result[i] = binaryString_shift1[i] == binaryString_shift2[i] ? '0' : '1';
                    result[i] = result[i] == binaryString_shift3[i] ? '0' : '1';
                }
                r = new string(result);
                return Convert.ToInt32(r, 2);
            }
            return Convert.ToInt32(r, 2);
        }
        public string shift_binary(string S)
        {
            // input : binary
            string r = "";
            string p = "00011011";
            string newbinaryString = S.PadRight(S.Length + 1, '0');

            if (newbinaryString[0] == '1')
            {
                newbinaryString = newbinaryString.Substring(1);
                char[] result = new char[8];
                for (int i = 0; i < 8; i++)
                {
                    result[i] = newbinaryString[i] == p[i] ? '0' : '1';
                }
                r = new string(result);
            }
            else
            {
                newbinaryString = newbinaryString.Substring(1);
                r = newbinaryString;
            }

            return r;
        }
    }
}
