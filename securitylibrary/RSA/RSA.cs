using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            long n = p * q;
            long C = 1;
            for (int i = 0; i < e; i++)
            {
                C = (C * (M % n)) % n;
            }    
            return Convert.ToInt32(C);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int n_Q = (p - 1) * (q - 1);
            ExtendedEuclid extendedEuclid = new ExtendedEuclid();
            int d = extendedEuclid.GetMultiplicativeInverse(e, n_Q);
            long M = 1;
            for (int i = 0; i < d; i++)
            {
                M = (M * (C % n)) % n;
            }
            return Convert.ToInt32(M);
        }
    }
}
