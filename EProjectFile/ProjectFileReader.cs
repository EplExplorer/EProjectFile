using QIQI.EProjectFile.Encryption;
using QIQI.EProjectFile.Internal;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using static QIQI.EProjectFile.EplDocument;

namespace QIQI.EProjectFile
{
    public class ProjectFileReader : IDisposable
    {
        public delegate string OnInputPassword(string passwordHint);
        public bool IsFinish { get; private set; } = false;

        private BinaryReader reader;
        public bool CryptEC { get; } = false;

        public ProjectFileReader(Stream stream, OnInputPassword inputPassword = null, bool ignoreVersion = false, DocumentType type = DocumentType.Auto)
        {
            reader = new BinaryReader(stream, Encoding.GetEncoding("gbk"));

            int magicHigh = reader.ReadInt32();
            int magicLow = 0;

            if (magicHigh == 0x454C5457) // WTLE 加密文件
            {

                int majorVersion = reader.ReadInt16();
                int minorVersion = reader.ReadInt16();

                // 忽略版本
                if (!ignoreVersion)
                {
                    if (majorVersion > 1 || minorVersion > 2) // 易语言当前最新加密版本为1.2
                    {
                        throw new Exception($"不支持的加密版本 {majorVersion}.{minorVersion}");
                    }
                }

                if (type == DocumentType.Auto)
                {

                    // 通过tips长度来判断是哪种加密 按易语言规定tips最长500个字符 所以后面两位必定是0
                    type = reader.ReadUInt32() >> 16 == 0 ? DocumentType.Module : DocumentType.Source;
                    reader.BaseStream.Position -= 4;
                }

                switch (type)
                {
                    case DocumentType.Source:
                        {
                            string password = inputPassword?.Invoke(null);
                            if (string.IsNullOrEmpty(password))
                            {
                                throw new Exception("没有输入密码 或 未正确响应InputPassword事件");
                            }
                            const int lengthOfRead = 8;
                            var cryptoTransform = new EStdCryptoTransform(EplSecret.EStd.Factory.Create(Encoding.GetEncoding("gbk").GetBytes(password)));

                            // 分块的时候，是不区分加密与非加密部分的，不进行 SeekToBegin 直接解密会导致分块错误
                            // 然而我们不能保证 Stream 一定 CanSeek，因此使用 PrefixedStream
                            var cryptoStream = new CryptoStream(new PrefixedStream(stream, new byte[lengthOfRead]), cryptoTransform, CryptoStreamMode.Read);

                            // 跳过非加密部分（但使得 CryptoStream 按与加密部分相同的方式来将这些数据考虑进分块过程）
                            cryptoStream.Read(new byte[lengthOfRead], 0, lengthOfRead);

                            reader = new BinaryReader(cryptoStream);

                            if (!reader.ReadBytes(cryptoTransform.SecretId.Length).SequenceEqual(cryptoTransform.SecretId))
                            {
                                throw new Exception("密码错误");
                            }
                        }
                        break;
                    case DocumentType.Module:
                        {
                            CryptEC = true;
                            int tip_bytes = reader.ReadInt32();
                            string tip = reader.ReadStringWithFixedLength(Encoding.GetEncoding("gbk"), tip_bytes);
                            string password = inputPassword?.Invoke(tip);
                            if (string.IsNullOrEmpty(password))
                            {
                                throw new Exception("没有输入密码 或 未正确响应InputPassword事件");
                            }
                            int lengthOfRead = 4 /* [int]magic1 */ + 4 /* [int]magic2 */ + 4 /* [int]tip_bytes */ + tip_bytes;
                            var cryptoTransform = new CryptoECTransform(EplSecret.EC.Factory.Create(Encoding.GetEncoding("gbk").GetBytes(password)));

                            // 分块的时候，是不区分加密与非加密部分的，不进行 SeekToBegin 直接解密会导致分块错误
                            // 然而我们不能保证 Stream 一定 CanSeek，因此使用 PrefixedStream
                            var cryptoStream = new CryptoStream(new PrefixedStream(stream, new byte[lengthOfRead]), cryptoTransform, CryptoStreamMode.Read);

                            // 跳过非加密部分（但使得 CryptoStream 按与加密部分相同的方式来将这些数据考虑进分块过程）
                            cryptoStream.Read(new byte[lengthOfRead], 0, lengthOfRead);

                            reader = new BinaryReader(cryptoStream);

                            if (!reader.ReadBytes(cryptoTransform.SecretId.Length).SequenceEqual(cryptoTransform.SecretId))
                            {
                                throw new Exception("密码错误");
                            }
                        }
                        break;
                }

                // 读取解密之后的magic
                magicHigh = reader.ReadInt32();
            }

            // 读取magic低32位
            magicLow = reader.ReadInt32();

            if (magicHigh != 0x54574E43 || magicLow != 0x47525045) // CNWTEPRG
            {
                throw new Exception("不是易语言工程文件");
            }
        }

        public RawSectionInfo ReadSection()
        {
            if (IsFinish) 
            {
                throw new EndOfStreamException();
            }
            RawSectionInfo section = new RawSectionInfo();
            if (!(reader.ReadInt32() == 0x15117319))
            {
                throw new Exception("Magic错误");
            }
            reader.ReadInt32(); // Skip InfoCheckSum
            section.Key = reader.ReadInt32();
            section.Name = DecodeName(section.Key, reader.ReadBytes(30));
            reader.ReadInt16(); // 对齐填充（确认于易语言V5.71）
            reader.ReadInt32(); // Skip Index
            section.IsOptional = reader.ReadInt32() != 0;
            reader.ReadInt32(); // Skip DataCheckSum
            int dataLength = reader.ReadInt32();
            if (CryptEC)
            {
                dataLength ^= 1;
            }
            reader.ReadBytes(40); // 保留未用（确认于易语言V5.71）
            section.Data = new byte[dataLength];
            reader.Read(section.Data, 0, dataLength);
            if (section.Key == 0x07007319) 
            {
                IsFinish = true;
            }
            return section;
        }


        private static string DecodeName(int key, byte[] encodedName)
        {
            if (encodedName == null)
            {
                return string.Empty;
            }
            byte[] r = (byte[])encodedName.Clone();
            if (key != 0x07007319)
            {
                var keyBytes = unchecked(new byte[] { (byte)key, (byte)(key >> 8), (byte)(key >> 16), (byte)(key >> 24) });
                for (int i = 0; i < r.Length; i++)
                {
                    r[i] ^= keyBytes[(i + 1) % 4];
                }
            }

            int count = Array.IndexOf<byte>(r, 0);
            if (count != -1)
            {
                var t = new byte[count];
                Array.Copy(r, t, count);
                r = t;
            }

            return Encoding.GetEncoding("gbk").GetString(r);
        }

        #region IDisposable Support
        private bool disposedValue = false; // 要检测冗余调用

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    reader.Dispose();
                }
                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
