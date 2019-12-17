using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using System.Security.Cryptography;
using Microsoft.Azure.KeyVault.WebKey;
using System.Text;
using System.IO;
using PemUtils;

namespace PemFunctionApp
{
    public class PemFunctionApp
    {
        private ILogger _logger;

        [FunctionName("PemFunctionApp")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            _logger = log;

            _logger.LogInformation("Triggering function app to read PEM key v1.");

            string name = $"Hello {DateTime.Now}";

            await ReadKeyFromVault();

            await ReadKeyFromPemFile();

            return name != null
                ? (ActionResult)new OkObjectResult($"Hello, {name}")
                : new BadRequestObjectResult("Please pass a name on the query string or in the request body");
        }

        public async Task ReadKeyFromVault()
        {
            
            try
            {
                _logger.LogInformation($"Keyvault driven approach.");
                var kvUri = "https://devkvpmtengineshared.vault.azure.net/keys/encryption-key/dc190f1de6604bdab494f50d0ce98bb7";
                _logger.LogInformation($"Read Key From KeyVault: {kvUri} ");
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var kvClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
                
                _logger.LogInformation($"Getting Key from Vault.");
                var keyResult = await kvClient.GetKeyAsync(kvUri);

                _logger.LogInformation($"Exponent:  {Convert.ToBase64String(keyResult.Key.E)}");
                _logger.LogInformation($"Modulus {Convert.ToBase64String(keyResult.Key.N)}");

                var rsaParameter = keyResult.Key.ToRSAParameters();
                var plainTextData = "Hello World";

                _logger.LogInformation($"Encrypting data using RSA parameters.");
                var provider = new RSACryptoServiceProvider();
                provider.ImportParameters(rsaParameter);
                var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainTextData);

                var edata = provider.Encrypt(bytesPlainTextData, true);

                _logger.LogInformation($"Decrpyting....... {edata.Length}");

                var decryptedData = await kvClient.DecryptAsync(kvUri, JsonWebKeyEncryptionAlgorithm.RSAOAEP, edata);
                var decryptedText = Encoding.Unicode.GetString(decryptedData.Result);

                _logger.LogInformation($"Decrpyted data:{decryptedText}");
                _logger.LogInformation("Done!");
            }
            catch (Exception ex)
            {
                _logger.LogInformation(ex.Message);
            }

        }

        public async Task ReadKeyFromPemFile()
        {
            try
            {
                _logger.LogInformation($"PEM Approach.");

                var kvUri = "https://devkvpmtengineshared.vault.azure.net/keys/encryption-key/dc190f1de6604bdab494f50d0ce98bb7";
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var kvClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
                
                RSAParameters rsaParameter;
                var stream = new MemoryStream();
                var writer = new StreamWriter(stream);
                var s = GetPEMString();

                writer.Write(s.ToString());
                writer.Flush();
                stream.Position = 0;

                using (var reader = new PemReader(stream))
                {
                    rsaParameter = reader.ReadRsaKey();
                }
                
                var plainTextData = "Hello World";

                _logger.LogInformation($"PEM Encrypting data using RSA parameters.");
                var provider = new RSACryptoServiceProvider();
                provider.ImportParameters(rsaParameter);
                var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainTextData);

                var edata = provider.Encrypt(bytesPlainTextData, true);

                _logger.LogInformation($"PEM Decrpyting....... {edata.Length}");

                var decryptedData = await kvClient.DecryptAsync(kvUri, JsonWebKeyEncryptionAlgorithm.RSAOAEP, edata);
                var decryptedText = Encoding.Unicode.GetString(decryptedData.Result);

                _logger.LogInformation($"PEM Decrpyted data:{decryptedText}");
                _logger.LogInformation("PEM Done!");

            }

            catch (Exception ex)
            {
                _logger.LogInformation(ex.Message);
            }

        }

        private static StringBuilder GetPEMString()
        {
            var sb = new StringBuilder();

            sb.AppendLine("-----BEGIN PUBLIC KEY-----");
            sb.AppendLine("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoRD2OoZJpGGmqOc0kaO1");
            sb.AppendLine("3GAoaEFV9djwc0pWeoq+g8g1Z+6Pn61HJDE18XUxNDjPUGx92qOeruUEZOSGKcIu");
            sb.AppendLine("/647xJ3oRxAi/Q3NS2FARFzHCnczJjEarN9Fyk8worOyKpc/9TAGBW+R3rOcSihr");
            sb.AppendLine("GZYfq0ruK6DwVBNm3BiZJQJpWlkLhb5ehOlgAxbRyvoBLQSmG/Z5s8WbhMNiuIjU");

            sb.AppendLine("9Pwf8lnco4iylDiff5fksTDILfRF4R0YhPxsic47NOLSWvVVnaXp8gwiiXPwKNoi");
            sb.AppendLine("TTSuQNdO02n4++b2h+tAmZ20oiL0Q49S2YDlrxmDVFNYGsdo21WI8SFbxm201KZp");
            sb.AppendLine("IJsDUaeP8KBMjOYtsW1en0VpTqD6htEbzJuVa+9AFRh/tPY9c4LO+VuPTnClKNX4");
            sb.AppendLine("6bbDDoatyKesHQTjCrwR2ohx2+tMKAaR2vv/I7pX9EkyOE8TOfBacB4J0sU104ja");
            sb.AppendLine("qFFR7IyN2YWx+UaDW4vC4BUoX/tVNRJPgEJWe4EvA+FtPjjP6d5n8l7vgtg3q04d");

            sb.AppendLine("F2z1do6kRHjvll5n8HITyF5on9gJfAFS0S3Q98x6dI06mj64gpltDdGQrDdojQE9");
            sb.AppendLine("shp/Uoi0SDaI1asLbsbw5T37R7UzOTGPGg4d1DDo/XSsRYFTt5oKwt1k66H0WPBm");
            sb.AppendLine("8G1Xw8qnXxtdZJjZPOiVLHcCAwEAAQ==");
            sb.AppendLine("-----END PUBLIC KEY-----");

            return sb;
        }

        public async Task ReadKeyFromPem()
        {
            var kvUri = "https://devkvpmtengineshared.vault.azure.net/keys/encryption-key/dc190f1de6604bdab494f50d0ce98bb7";
            _logger.LogInformation($"Read Key From KeyVault: {kvUri} ");
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var kvClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
            var keyResult = await kvClient.GetKeyAsync(kvUri);
            var rsaParameter = keyResult.Key.ToRSAParameters();
        }

        public async Task Encrypt(RSAParameters rsaPublicParams, string plainTextData = "Hello")
        {
            var provider = new RSACryptoServiceProvider();
            provider.ImportParameters(rsaPublicParams);
            var bytesPlainTextData = System.Text.Encoding.Unicode.GetBytes(plainTextData);
            provider.Encrypt(bytesPlainTextData, false);
        }
    }
}
