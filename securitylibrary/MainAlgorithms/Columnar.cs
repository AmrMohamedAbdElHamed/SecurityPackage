using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int row = 0;
            int pre = -1;
            int diff = -1;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == cipherText[row])
                {
                    if (pre == -1 && diff == -1)
                    {
                        pre = i;
                        row++;
                    }
                    else if (diff == -1)
                    {
                        if (i - pre == 1)
                        {
                            pre = i;
                            continue;
                        }
                        diff = i - pre;
                        pre = i;
                        row++;
                    }
                    else
                    {
                        if (i - pre == diff)
                        {
                            pre = i;
                            row++;
                        }
                    }

                }

            }

            int col = plainText.Length / row;
            if (plainText.Length % row != 0)
            {
                col++;
            }
            List<int> key = new List<int>();
            for (int i = 0; i < col; i++)
                key.Add(0);
            int count = 0;
            for (int i = 0; i < col; i++)
            {
                count = 0;
                for (int j = 0; j < cipherText.Length; j += row)
                {
                    count++;
                    if (cipherText[j] == plainText[i] && cipherText[j + 1] == plainText[i + col])
                    {
                        key[i] = count;
                        break;
                    }
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            int col = key.Count();
            int row = cipherText.Length / col;

            if (cipherText.Length % col != 0)
            {
                row++;
            }

            string plain = "";
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if ((i + ((key[j] - 1) * row)) >= cipherText.Length)
                        break;
                    plain += cipherText[i + ((key[j] - 1) * row)];
                }
            }

            return plain;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            int col = key.Count();
            int row = plainText.Length / col;

            if (plainText.Length % col != 0)
            {
                row++;
            }

            int[] rev_key = new int[col];
            for (int i = 0; i < col; i++)
            {
                rev_key[key[i] - 1] = i;
            }

            int count = 0;
            string cipher = "";
            for (int i = 0; i < col; i++)
            {
                count = rev_key[i];
                for (int j = 0; j < row; j++)
                {
                    if (count >= plainText.Length)
                        break;
                    cipher += plainText[count];
                    count += col;
                }
            }
            return cipher;
        }
    }
}
