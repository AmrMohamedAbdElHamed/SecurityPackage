using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int pub_a = PowMod(alpha, xa, q);
            int pub_b = PowMod(alpha, xb, q);

            List<int> keys = new List<int>();
            keys.Add(PowMod(pub_b, xa, q));
            keys.Add(PowMod(pub_a, xb, q));

            return keys;
        }
        public int PowMod(int A, int B,int mod)
        {
            int ret = 1;
            A %= mod;
            for (int i = 0; i < B; i++)
            {
                ret = (ret * A) % mod;
            }
            return ret % mod;
        }
    }
}
