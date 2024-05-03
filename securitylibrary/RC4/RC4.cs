using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {

            int[] p = new int[cipherText.Length];
            int[] k = new int[key.Length];
            bool hexa = cipherText.StartsWith("0x");
            if (hexa)
            {
                cipherText = cipherText.Substring(2);
                key = key.Substring(2);


                p = Enumerable.Range(0, cipherText.Length)
                                 .Where(x => x % 2 == 0)
                                 .Select(x => Convert.ToInt32(cipherText.Substring(x, 2), 16))
                                 .ToArray();

                k = Enumerable.Range(0, key.Length)
                                 .Where(x => x % 2 == 0)
                                 .Select(x => Convert.ToInt32(key.Substring(x, 2), 16))
                                 .ToArray();

            }
            else
            {
                for (int i = 0; i < cipherText.Length; i++)
                {
                    p[i] = Convert.ToInt32(cipherText[i]);
                    k[i] = Convert.ToInt32(key[i]);
                }
            }
            int[] newKey = generateKey(k);
            int[] result = new int[p.Length];
            for (int i = 0; i < p.Length; i++)
            {
                result[i] = p[i] ^ newKey[i];
            }
            string r = "";
            if (hexa)
            {
                r = "0x";
                for (int i = 0; i < result.Length; i++)
                {
                    r += result[i].ToString("X");
                }
            }
            else
            {
                for (int i = 0; i < result.Length; i++)
                {
                    r += (char)result[i];
                }
            }
            return r;
        }

        public override  string Encrypt(string plainText, string key)
        {
            int[] p = new int[plainText.Length];
            int[] k = new int[key.Length];
            bool hexa= plainText.StartsWith("0x");
            if (hexa)
            {
                plainText = plainText.Substring(2);
                key = key.Substring(2);


                p = Enumerable.Range(0, plainText.Length)
                                 .Where(x => x % 2 == 0)
                                 .Select(x => Convert.ToInt32(plainText.Substring(x, 2), 16))
                                 .ToArray();

                k = Enumerable.Range(0, key.Length)
                                 .Where(x => x % 2 == 0)
                                 .Select(x => Convert.ToInt32(key.Substring(x, 2), 16))
                                 .ToArray();

            }
            else
            {
                for (int i = 0; i < plainText.Length; i++)
                {
                    p[i] = Convert.ToInt32(plainText[i]);
                    k[i] = Convert.ToInt32(key[i]);
                }
            }
            int[] newKey = generateKey(k);
            int[] result=new int[p.Length];
            for (int i = 0; i < p.Length; i++)
            {
                result[i] = p[i] ^ newKey[i];
            }
            string r="";
            if (hexa)
            {
                r = "0x";
                for (int i = 0; i < result.Length; i++)
                {
                    r += result[i].ToString("X");
                }
            }
            else
            {
                for (int i = 0; i < result.Length; i++)
                {
                    r += (char)result[i];
                }
            }
            return r;
            //throw new NotImplementedException();
        }


        public int[] generateKey(int[] k)
        {

            int[] S = new int[256];
            int[] T = new int[256];
            //Initialization of S and T
            for (int i = 0; i < S.Length; i++)
            {
                S[i] = i;
                T[i] = k[i % k.Length];
            }

            //Initial permutation of S
            int j = 0;
            int temp = 0;
            for (int i = 0; i < S.Length; i++)
            {
                j = (j + S[i] + T[i]) % 256;

                temp = S[i];
                S[i] = S[j];
                S[j] = temp;

            }

            //Generation of Key stream K
            int index = 0;
            j = 0;
            int t = 0;
            int[] newKey = new int[k.Length];
            for (int i = 0; i < k.Length; i++)
            {
                index = (index + 1) % 256;
                j = (j + S[index]) % 256;

                temp = S[index];
                S[index] = S[j];
                S[j] = temp;

                t = (S[index] + S[j]) % 256;
                newKey[i] = S[t];

            }
            return newKey;

        } 
    }
}
