using QIQI.EProjectFile;
using System;
using System.IO;
using System.Text;
using static QIQI.EProjectFile.ProjectFileReader;

namespace Test
{
    internal class Program
    {

        static string InputPassword(string tips)
        {

            // 返回测试文件密码
            return "123456";
        }

        // 测试读取加密易文件
        static void TestDecrypt(EplDocument doc)
        {
            try
            {
                doc.Load(File.OpenRead("../../../assets/encrypted.ec"), InputPassword);
            }
            catch(Exception e)
            {
                Console.WriteLine("读取加密易文件 - 失败");
                Console.WriteLine(e);
                return;
            }
            Console.WriteLine("读取加密易文件 - 成功");
        }

        // 测试版本混淆加密易文件
        static void TestDecryptObfuscate(EplDocument doc)
        {
            try
            {
                doc.Load(File.OpenRead("../../../assets/encrypted-obfuscate.ec"), InputPassword);
            }
            catch (Exception e)
            {
                Console.WriteLine("读取版本混淆加密易文件 - 失败");
                Console.WriteLine(e);
                return;
            }
            Console.WriteLine("读取版本混淆加密易文件 - 成功");
        }

        static void Main(string[] args)
        {

            Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);

            var doc = new EplDocument();

            TestDecrypt(doc);
            TestDecryptObfuscate(doc);

        }
    }
}
