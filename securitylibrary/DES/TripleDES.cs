using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            //throw new NotImplementedException();
            DES des = new DES();
            return des.Decrypt(des.Encrypt(des.Decrypt(cipherText, key[0]), key[1]), key[0]);
        }

        public string Encrypt(string plainText, List<string> key)
        {
            //throw new NotImplementedException();
            DES des = new DES();
            return des.Encrypt(des.Decrypt(des.Encrypt(plainText, key[0]), key[1]), key[0]);
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
