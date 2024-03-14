using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int row = 2;

            int[,] matrix = new int[row, row];
            int[,] cipher_M = new int[row, row];
            int[,] flipped_inv_matrix = new int[row, row];
            int[,] inv_matrix = new int[row, row];
            int[,] key_M = new int[row, row];
            List<int> key = new List<int>();
            int try_i = 0;
            int try_j = 0;
            int det = 0;
            int inv_det = 0;
            while((try_i + row) < (plainText.Count() / 2))
            {
                for (int j = 0; j < row; j++)
                {
                    for (int i = 0; i < row; i++)
                    {
                        matrix[j, i] = plainText[(i*try_i)+(i*try_j) + j];
                        cipher_M[j, i] = cipherText[(i * try_i) + (i * try_j) + j];
                    }
                }
                det = ((CalculateDeterminant(matrix) % 26) + 26) % 26;

                inv_det = 0;

                for (int i = 1; i < 26; i++)
                {
                    if ((det * i) % 26 == 1)
                    {
                        inv_det = i;
                        break;
                    }

                }
                if (inv_det != 0 && det != 0)
                    break;
                try_j +=2;
                if(try_j == plainText.Count)
                {
                    try_i += 2;
                    try_j = try_i;
                }
            }

            if (inv_det == 0 || det == 0)
                throw new SecurityLibrary.InvalidAnlysisException();
            //step three
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    int sub_det = SubDeterminant(matrix, i, j);
                    flipped_inv_matrix[i, j] = (((inv_det * ((i + j) % 2 == 0 ? 1 : -1) * sub_det) % 26) + 26) % 26;
                }
            }
            //step four
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    inv_matrix[j,i] = flipped_inv_matrix[i, j];
                }
            }

            key_M = MultiplyMatrices(cipher_M, inv_matrix);

            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    key.Add(key_M[i, j]);
                }
            }

            return key;
        }

        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            List<int> plainText_L = string_list(plainText);
            List<int> cipher_L = string_list(cipherText);
            List<int> key_L = Analyse(plainText_L, cipher_L);
            return list_string(key_L);
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int row = (int)Math.Sqrt(key.Count);

            int[,] matrix = new int[row, row];
            int[,] flipped_inv_matrix = new int[row, row];
            List<int> inv_matrix_L = new List<int>();
            List<int> plain_text = new List<int>();

            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    matrix[i, j] = key[(i * row) + j];
                }
            }
            //calc dete
            int det = ((CalculateDeterminant(matrix) % 26 ) + 26) % 26;

            //calc inv dete
            int inv_det = 0;
            
            for (int i = 1; i < 26; i++)
            {
                if ((det * i) % 26 == 1)
                {
                    inv_det = i;
                    break;
                }

            }
            if (inv_det == 0 || det == 0)
                throw new Exception();
            //step three
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    int sub_det = SubDeterminant(matrix, i, j);
                    flipped_inv_matrix[i, j] = (((inv_det * ((i + j) % 2 == 0 ? 1 : -1) * sub_det) % 26) + 26) % 26;
                }
            }
            
            //step four
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    inv_matrix_L.Add(flipped_inv_matrix[j, i]);
                }
            }

            for (int i = 0; i < cipherText.Count; i += row)
            {
                for (int j = 0; j < row; j++)
                {
                    int sum = 0;
                    for (int y = 0; y < row; y++)
                    {
                        sum += cipherText[i + y] * inv_matrix_L[(j * row) + y];
                    }
                    plain_text.Add(sum % 26);
                }
            }

            return plain_text;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            List<int> cipher_L= string_list(cipherText);
            List<int> key_L = string_list(key);
            List<int> plainText_L = Decrypt(cipher_L, key_L);
            return list_string(plainText_L);
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int row = (int)Math.Sqrt(key.Count);
            List<int> cipher = new List<int>();
            for (int i = 0; i < plainText.Count; i += row)
            {
                for (int j = 0; j < row; j++)
                {
                    int sum = 0;
                    for (int y = 0; y < row; y++)
                    {
                        sum += plainText[i + y] * key[(j * row) + y];
                    }
                    cipher.Add(sum % 26);
                }
            }

            return cipher;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            List<int> plainText_L = string_list(plainText);
            List<int> key_L = string_list(key);
            List<int> cipher_L = Encrypt(plainText_L, key_L);
            return list_string(cipher_L);
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();
            int row = 3;

            int[,] matrix = new int[row, row];
            int[,] cipher_M = new int[row, row];
            int[,] flipped_inv_matrix = new int[row, row];
            int[,] inv_matrix = new int[row, row];
            int[,] key_M = new int[row, row];
            List<int> key = new List<int>();
            int try_i = 0;
            int try_j = 0;
            int det = 0;
            int inv_det = 0;
            while (((try_i*2) +try_j+row) < (plain3.Count()))
            {
                for (int j = 0; j < row; j++)
                {
                    for (int i = 0; i < row-1; i++)
                    {
                        matrix[j, i] = plain3[(i * try_i) + (i * try_j) + j + try_i];
                        cipher_M[j, i] = cipher3[(i * try_i) + (i * try_j) + j + try_i];
                        if(i == 1)
                        {
                            matrix[j, i + 1] = plain3[(i * try_i) + (i * try_j) + j + try_i + row];
                            cipher_M[j, i + 1] = cipher3[(i * try_i) + (i * try_j) + j + try_i + row];
                        }
                    }
                }
                det = ((CalculateDeterminant(matrix) % 26) + 26) % 26;

                inv_det = 0;

                for (int i = 1; i < 26; i++)
                {
                    if ((det * i) % 26 == 1)
                    {
                        inv_det = i;
                        break;
                    }

                }
                if (inv_det != 0 && det != 0)
                    break;
                try_j += row;
                if (try_j+row >= plain3.Count)
                {
                    try_i += row;
                    try_j = 0;
                }
            }

            if (inv_det == 0 || det == 0)
                throw new SecurityLibrary.InvalidAnlysisException();
            //step three
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    int sub_det = SubDeterminant(matrix, i, j);
                    flipped_inv_matrix[i, j] = (((inv_det * ((i + j) % 2 == 0 ? 1 : -1) * sub_det) % 26) + 26) % 26;
                }
            }
            //step four
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    inv_matrix[j, i] = flipped_inv_matrix[i, j];
                }
            }

            key_M = MultiplyMatrices(cipher_M, inv_matrix);

            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    key.Add(key_M[i, j]);
                }
            }

            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            //throw new NotImplementedException();
            cipher3 = cipher3.ToLower();
            List<int> plainText_L = string_list(plain3);
            List<int> cipher_L = string_list(cipher3);
            List<int> key_L = Analyse3By3Key(plainText_L, cipher_L);
            return list_string(key_L);
        }

        //Helper function
        public int CalculateDeterminant(int[,] matrix)
        {
            if (matrix.GetLength(0) != matrix.GetLength(1))
            {
                throw new ArgumentException("Matrix must be square.");
            }
            int size = matrix.GetLength(0);
            if(size == 1)
            {
                return matrix[0, 0];
            }
            if (size == 2)
            {
                return matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];
            }

            int det = 0;
            for (int i = 0; i < size; i++)
            {
                int[,] subMatrix = new int[size - 1, size - 1];
                for (int j = 1; j < size; j++)
                {
                    for (int k = 0; k < size; k++)
                    {
                        if (k < i)
                        {
                            subMatrix[j - 1, k] = matrix[j, k];
                        }
                        else if (k > i)
                        {
                            subMatrix[j - 1, k - 1] = matrix[j, k];
                        }
                    }
                }

                det += (int)Math.Pow(-1, i) * matrix[0, i] * CalculateDeterminant(subMatrix);
            }

            return det;
        }

        public int SubDeterminant(int[,] matrix, int row_remove, int col_remove)
        {
            int size = matrix.GetLength(0);
            int[,] sub = new int[size - 1, size - 1];
            int sub_i = 0;
            int sub_j = 0;

            for (int i = 0; i < size; i++)
            {
                if (i == row_remove)
                    continue;
                sub_j = 0;
                for (int j = 0; j < size; j++)
                {
                    if (j == col_remove)
                        continue;
                    sub[sub_i, sub_j] = matrix[i, j];
                    sub_j++;
                }
                sub_i++;
            }

            int sub_det = CalculateDeterminant(sub);
            return sub_det;
        }

        public List<int> string_list(string text)
        {
            List<int> list = new List<int>();
            for (int i = 0; i < text.Count(); i++)
            {
                list.Add(text[i] - 97);
            }
            return list;
        }

        public string list_string(List<int> list)
        {
            string text = "";
            for (int i = 0; i < list.Count; i++)
            {
                text += (char)(list[i] + 97);
            }

            return text;
        }

        public int[,] MultiplyMatrices(int[,] matrix1, int[,] matrix2)
        {
            int rows1 = matrix1.GetLength(0);
            int cols1 = matrix1.GetLength(1);
            int cols2 = matrix2.GetLength(1);

            int[,] result = new int[rows1, cols2];

            for (int i = 0; i < rows1; i++)
            {
                for (int j = 0; j < cols2; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < cols1; k++)
                    {
                        sum += matrix1[i, k] * matrix2[k, j];
                    }
                    result[i, j] = sum % 26;
                }
            }
            return result;
        }
    }
}
