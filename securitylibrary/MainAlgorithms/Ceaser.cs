using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipher = "";
            foreach (char letter in plainText)
            {
                cipher += (char)(((letter+key-97)%26)+97);
            }
            return cipher;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";
            foreach (char letter in cipherText)
            {
                plainText += (char)(((((letter - key - 97) % 26) + 26) % 26) + 97);
            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            return ((cipherText[0] + 32 - plainText[0]) + 26) % 26;
        }
    }
}
