using System;
using System.Linq;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            //   throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            string DE = "";
            char[,] Matrix = new char[5, 5];
            string stringOfMatrix = "";
            bool insertI = true;
            for (int i = 0; i < key.Length; i++)
            {
                if (!stringOfMatrix.Contains(key[i]) && key[i] == 'j' && insertI)
                {
                    stringOfMatrix += 'i';
                    insertI = false;
                    continue;
                }
                else if (!stringOfMatrix.Contains(key[i]) && key[i] != 'j')
                    stringOfMatrix += key[i];
                else
                    continue;
            }
            for (int i = 0; i < alphabet.Length; i++)
            {
                if (!stringOfMatrix.Contains(alphabet[i]))
                    stringOfMatrix += alphabet[i];
                else
                    continue;
            }
            int x = 0;
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                {
                    Matrix[i, j] = stringOfMatrix[x];
                    x++;
                }

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char x1 = cipherText[i], x2 = cipherText[i + 1];
                int x1I = 0, x1J = 0, x2I = 0, x2J = 0;
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (Matrix[j, k] == x1)
                        {
                            x1I = j; x1J = k;
                        }
                        else if (Matrix[j, k] == x2)
                        {
                            x2I = j; x2J = k;
                        }
                    }
                }
                if (x1J == x2J)
                {
                    DE += Matrix[((x1I + 4) % 5), x1J];
                    DE += Matrix[((x2I + 4) % 5), x2J];
                }
                else if (x1I == x2I)
                {
                    DE += Matrix[x1I, ((x1J + 4) % 5)];
                    DE += Matrix[x2I, ((x2J + 4) % 5)];
                }
                else
                {
                    DE += Matrix[x1I, x2J];
                    DE += Matrix[x2I, x1J];
                }

            }
            string res = DE;
            if (DE[DE.Length - 1] == 'x')
            {
                res = res.Remove(DE.Length - 1);
            }
            string FDE = "";
            int incre = 0;
            for (int i = 0; i < res.Length; i++)
            {
                if (DE[i] == 'x')
                {
                    if (DE[i - 1] == DE[i + 1])
                    {
                        if (i + incre < res.Length && (i - 1) % 2 == 0)
                        {
                            res = res.Remove(i + incre, 1);
                            incre--;
                        }
                    }
                }
            }

            FDE += res;
            return FDE;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            #region var
            plainText = plainText.ToLower();
            string EN = "";
            char[,] Matrix = new char[5, 5];
            string stringOfMatrix = "";
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            int cnt = 0;
            #endregion
            for (int i = 0; i < key.Length; i++)
            {
                if (!stringOfMatrix.Contains(key[i]) && key[i] != 'j')
                    stringOfMatrix += key[i];
                else
                    continue;
            }
            for (int i = 0; i < alphabet.Length; i++)
            {
                if (!stringOfMatrix.Contains(alphabet[i]))
                    stringOfMatrix += alphabet[i];
                else
                    continue;
            }
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    Matrix[i, j] = stringOfMatrix[cnt];
                    cnt++;
                }
            }
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Substring(0, i + 1) + 'x' + plainText.Substring(i + 1);
                }

            }
            if (plainText.Length % 2 == 1) plainText += 'x';
            for (int i = 0; i < plainText.Length; i += 2)
            {
                char x1 = plainText[i], x2 = plainText[i + 1];
                int x1I = 0, x1J = 0, x2I = 0, x2J = 0;
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (Matrix[j, k] == x1)
                        {
                            x1I = j; x1J = k;
                        }
                        else if (Matrix[j, k] == x2)
                        {
                            x2I = j; x2J = k;
                        }
                    }
                }
                if (x1I == x2I)
                {
                    EN += Matrix[x1I, ((x1J + 1) % 5)];
                    EN += Matrix[x2I, ((x2J + 1) % 5)];
                }
                else if (x1J == x2J)
                {
                    EN += Matrix[((x1I + 1) % 5), x1J];
                    EN += Matrix[((x2I + 1) % 5), x2J];

                }
                else
                {
                    EN += Matrix[x1I, x2J];
                    EN += Matrix[x2I, x1J];
                }

            }
            return EN.ToUpper();

        }

    }
}