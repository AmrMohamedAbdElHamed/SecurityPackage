using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            
        }

        public string Decrypt(string cipherText, string key)
        {
            #region variable
            cipherText = cipherText.ToLower();
            char[,] table = new char[26, 26];
            char[] alphabet = new char[26];
            int firstIndex = -1;
            int secondIndex = -1;
            char[] res = new char[cipherText.Length];
            #endregion
            // Create indexing for table
            for (int i = 0; i < 26; i++)
            {
                alphabet[i] = (char)('a' + i);
            }

            // Create table
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    table[i, j] = alphabet[(i + j) % 26];
                }
            }

            // Search in table
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (key[i] == alphabet[j])
                        firstIndex = j;
                    if (firstIndex != -1)
                    {
                        for (int k = 0; k < 26; k++)
                        {
                            if (cipherText[i] == table[k, firstIndex])
                            {
                                secondIndex = k;
                                break;
                            }
                        }
                    }
                    if (firstIndex != -1 && secondIndex != -1)
                    {
                        res[i] = table[secondIndex, 0];
                        if (key.Length != cipherText.Length)
                        {
                            key = key + table[secondIndex, 0];
                        }
                        firstIndex = -1;
                        secondIndex = -1;
                        break;
                    }
                }
            }
            return new string(res);
        }

        public string Encrypt(string plainText, string key)
        {
            #region variable
            char[,] table = new char[26, 26];
            char[] alphabet = new char[26];
            string keyStream = "";
            char[] supKey = new char[plainText.Length-key.Length];
            int count = 0;
            int firstIndex = -1;
            int secendIndex = -1;
            char[] res = new char[plainText.Length];
            #endregion
            //create indexing for table 
            for (int i = 0; i < 26; i++)
            {
                alphabet[i] = (char)('a' + i);
            }
            //create table
            for (int i = 0; i < 26; i++)
            {
                for(int j = 0; j < 26; j++)
                {
                    table[i, j] = alphabet[(i + j) % 26];
                    /*
                    if (count < 25)
                        count = count%25;
                    table[j,i] = alphabet[count];
                    count++;
                    if (j == 25)
                        count++;*/
                }
            }
            //create keystream
            if (plainText.Length > key.Length)
            {
                for(int i = 0;i<(plainText.Length- key.Length);i++) 
                {
                    supKey[count] = plainText[count];
                    count++;
                }
                keyStream=key+ new string(supKey);
            }
            //serch in table
            for(int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0;j<alphabet.Length; j++)
                {
                    if (plainText[i] == alphabet[j])
                        firstIndex = j;
                    if (keyStream[i] == alphabet[j])
                        secendIndex = j;
                    //set value to result
                    if((firstIndex != -1) && (secendIndex != -1))
                    {
                        res[i] = table[firstIndex, secendIndex];
                        firstIndex = -1;
                        secendIndex=-1;
                        break;
                    }
                }
            }
            return new string(res);
        }
    }
}
