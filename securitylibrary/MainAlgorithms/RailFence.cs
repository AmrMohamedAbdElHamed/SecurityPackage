using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (char.ToLower(plainText[i]) == char.ToLower(cipherText[1]) &&
                    char.ToLower(plainText[i + key]) == char.ToLower(cipherText[2]))
                    break;
                key++;
            }


            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            int C_len = cipherText.Length;
            int P_len = C_len / key;
            if (C_len % key != 0)
            {
                P_len++;
            }
            string plainText = "";
            int count = 0;
            for (int i = 0; i < P_len; i++)
            {
                count = i;
                for (int j = 0; j < key; j++)
                {
                    plainText += cipherText[count];
                    count += P_len;
                    if (count >= C_len)
                        break;
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            int P_len = plainText.Length;
            string cipherText = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < P_len; j += key)
                {
                    if (plainText[j] == ' ')
                    {
                        j++;
                        if (j >= P_len)
                            break;
                    }
                    cipherText += plainText[j];
                }
            }
            return cipherText;
        }
    }
}
