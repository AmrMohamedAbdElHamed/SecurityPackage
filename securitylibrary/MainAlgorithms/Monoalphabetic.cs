using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            Dictionary<char, char> dic = new Dictionary<char, char>();
            HashSet<char> map = new HashSet<char>();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (!dic.ContainsKey(plainText[i]))
                {
                    dic.Add(plainText[i], cipherText[i]);
                    map.Add(cipherText[i]);
                }
            }
            string key = "";
            for (char c = 'a'; c <= 'z'; c++)
            {
                if (dic.ContainsKey(c))
                {
                    key += dic[c];
                }
                else
                {
                    char temp = (char)((((key.Last()) + 1) % 97) + 97);
                    while (map.Contains(temp))
                    {
                        temp++;
                    }
                    key += temp;
                    map.Add(temp);

                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText += (char)(key.IndexOf((char)(cipherText[i])) + 97);
            }

            return plainText;

        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string ciphertext = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                ciphertext += key[plainText[i] - 97];
            }
            return ciphertext;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>

        public string AnalyseUsingCharFrequency(string cipherText)
        {
            cipherText = cipherText.ToLower();
            char[] letterPercentage = {
            'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k',
            'x', 'j', 'q', 'z'};
            Dictionary<char, int> Freq_cipher = new Dictionary<char, int>();
            Dictionary<char, char> pairing = new Dictionary<char, char>();

            foreach (char c in cipherText)
            {
                if (Freq_cipher.ContainsKey(c))
                    Freq_cipher[c]++;
                else
                    Freq_cipher[c] = 1;
            }

            var sorted_freq = Freq_cipher.OrderByDescending(x => x.Value);

            int j = 0;
            foreach (var item in sorted_freq)
            {
                pairing[item.Key] = letterPercentage[j];
                j++;
            }

            string plaintext = "";
            foreach (char c in cipherText)
            {
                plaintext += pairing[c];
            }

            return plaintext;
        }
    }
}
