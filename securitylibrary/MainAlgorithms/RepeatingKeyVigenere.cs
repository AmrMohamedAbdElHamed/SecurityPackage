using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key= solveAnalyse(cipherText.ToLower(), plainText.ToLower());

            StringBuilder stringBuilder= new StringBuilder();
            string k;
            foreach (var item in key)
            {
                stringBuilder.Append(item);
                if (cipherText.ToLower().Equals(Encrypt(plainText, stringBuilder.ToString()).ToLower()))
                {
                    k = stringBuilder.ToString();
                    break;
                }
            }
            k= stringBuilder.ToString();
            return k;
        }

        public string Decrypt(string cipherText, string key)
        {
            if (cipherText.Length == key.Length)
                return solveDecrypt(cipherText.ToLower(), key.ToLower());
            else
            {
                key = extendkey(cipherText.ToLower(), key.ToLower());
                return solveDecrypt(cipherText.ToLower(), key.ToLower());
            }
        }

        public string Encrypt(string plainText, string key)
        {
            if (plainText.Length == key.Length)
                return solveEncrypt(plainText,key);
            else
            {
                key = extendkey( plainText,  key);
                return solveEncrypt(plainText, key);
            }
        }

        //helper function
        public string extendkey(string plainText, string key)
        {
            int i=0;
            int keyLength=key.Length;
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append(key);
            while (stringBuilder.Length!= plainText.Length)
            {
                stringBuilder.Append(key[i % keyLength]);
                i++;
            }
            return stringBuilder.ToString();
        }
        public string solveEncrypt(string plainText, string key)
        {
            string alphabetic = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToLower();
            Dictionary<char,int> alphaToindex=new Dictionary<char,int>();
            for (int i = 0; i < alphabetic.Length; i++)
            {
                alphaToindex.Add(alphabetic[i], i);
            }
            StringBuilder CT =new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = (alphaToindex[plainText[i]]+ alphaToindex[key[i]]) % 26;
                CT.Append(alphabetic[index]);
            }
          
            return CT.ToString();
        }
        public string solveDecrypt(string cipherText, string key)
        {
            string alphabetic = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToLower();
            Dictionary<char, int> alphaToindex = new Dictionary<char, int>();
            for (int i = 0; i < alphabetic.Length; i++)
            {
                alphaToindex.Add(alphabetic[i], i);
            }
            StringBuilder CT = new StringBuilder();
            for (int i = 0; i < cipherText.Length; i++)
            {
                int index = (alphaToindex[cipherText[i]] - alphaToindex[key[i]]) % 26;
                if (index <0)
                    index+=26;
                CT.Append(alphabetic[index]);
            }

            return CT.ToString();
        }
        public string solveAnalyse(string cipherText, string plainText)
        {
            string alphabetic = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToLower();
            Dictionary<char, int> alphaToindex = new Dictionary<char, int>();
            for (int i = 0; i < alphabetic.Length; i++)
            {
                alphaToindex.Add(alphabetic[i], i);
            }
            StringBuilder CT = new StringBuilder();
            for (int i = 0; i < cipherText.Length; i++)
            {
                int index = (alphaToindex[cipherText[i]] - alphaToindex[plainText[i]]) % 26;
                if (index < 0)
                    index += 26;
                CT.Append(alphabetic[index]);
            }
            
            return CT.ToString();
        }
        public string getKey(string plainText,string streamKey)
        {

            StringBuilder key = new StringBuilder();

            int j = 0;
            bool flag=true;
            for (int i = 0; i < streamKey.Length; i++)
            {
                if (!streamKey[i].Equals(plainText[j]))
                    key.Append(streamKey[i]);
                else
                {
                    int index = 0;
                    for (int k = i; k < streamKey.Length; k++)
                    {
                        if (!streamKey[k].Equals(plainText[index])) { 
                           flag = false;
                            break;
                        }

                        index++;

                    }
                    if(flag)
                        return key.ToString();
                   j++;
                }

            }

            return key.ToString();
        }
    }
}