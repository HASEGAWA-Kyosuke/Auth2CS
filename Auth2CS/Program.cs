using System;
using System.IO;
using System.Security.Cryptography;

namespace Auth2
{
    class Program
    {
        static void Main(string[] args) {
            PrintAuthCode("XXXXXXXXXXXXXXXX");
        }

        private static void PrintAuthCode(string secretKey) {
            const int timeUnit = 30;
            Console.WriteLine("      30--------20--------10--------0");
            while (true) {
                long currentTime = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds / 1000;
                long timeIndex = currentTime / timeUnit;
                long elapsedTime = currentTime % timeUnit;
                Console.Write("{0:d6} ", GetCode(secretKey, timeIndex));
                for (int i = 0; i < timeUnit; i++) {
                    Console.Write('>');
                    if (i >= elapsedTime) {
                        System.Threading.Thread.Sleep(1000);
                    }
                }
                Console.WriteLine();
            }
        }

        private static ulong GetCode(string secretKey, long timeIndex) {
            var mac = new HMACSHA1(Base32decode(secretKey));
            byte[] hash = mac.ComputeHash(ToByteArray(timeIndex));
            int offset = hash[19] & 0xF;
            ulong truncatedHash = (ulong)hash[offset] & 0x7F;
            for (int i = 1; i < 4; i++) {
                truncatedHash <<= 8;
                truncatedHash |= (ulong)hash[offset + i] & 0xFF;
            }
            return truncatedHash %= 1000000;
        }

        private static byte[] Base32decode(string secretKey) {
            const string b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";
            var buff = new MemoryStream(secretKey.Length * 5 / 8);
            for (int i = 0; i < buff.Capacity; i++) {
                int k = i * 8 / 5;
                uint b1 = (uint)b32.IndexOf(secretKey[k]) << (8 - 5);
                uint b2 = (uint)b32.IndexOf(secretKey[k + 1]) << (8 - 5);
                uint b3 = (i < buff.Capacity - 1) ? (uint)b32.IndexOf(secretKey[k + 2]) << (8 - 5) : 0;
                int sft1 = i * 8 % 5;
                int sft2 = sft1 - 5; 
                int sft3 = sft2 - 5;
                buff.WriteByte((byte)(Shift(b1, sft1) | Shift(b2, sft2) | Shift(b3, sft3)));
            }
            return buff.ToArray();
        }

        private static uint Shift(uint b, int shift) {
            return (shift > 0) ? b << shift : (shift < 0) ? b >> -shift : b;
        }

        private static byte[] ToByteArray(long x) {
            byte[] ba = BitConverter.GetBytes(x);
            for (int i = 0; i < ba.Length / 2; i++) {
                byte b = ba[i];
                ba[i] = ba[ba.Length - 1 - i];
                ba[ba.Length - 1 - i] = b;
            }
            return ba;
        }
    }
}
