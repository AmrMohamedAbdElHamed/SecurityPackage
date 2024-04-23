using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();
            #region var
            int Q;
            int A1=1,A2=0,A3=baseN;
            int B1=0,B2=1,B3=number;
            int temp1=B1,temp2=B2,temp3=B3;
            #endregion
            while (B3 != 0 && B3 != 1)
            {
                Q  = A3/B3;
                B1 = A1-(Q * temp1);
                B2 = A2-(Q * temp2);
                B3 = A3-(Q * temp3);
                A1 = temp1;
                A2 = temp2;
                A3 = temp3;
                temp1 = B1;
                temp2 = B2;
                temp3 = B3;
            }
            if (B3 == 0)
                return -1;
            if (B2 < 0)
                B2 += baseN;
            return B2;
        }
    }
}
