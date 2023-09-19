using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Text;
using Newtonsoft.Json.Linq;

namespace BCProxy
{
    public class Program
    {
        static string endpointsFile = "";
        const string ENCRYPT_KEY = "bc-proxy";

        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            endpointsFile = builder.Environment.ContentRootPath + "/endpoints.json";

            var app = builder.Build();
            app.MapPost("/{**path}", Execute);
            app.Run();
        }

        static async Task Execute(HttpContext httpContext)
        {
            Endpoints.Endpoint? target = null;

            try
            {
                if (!File.Exists(endpointsFile))
                    throw new Exception("No endpoints defined");

                StreamReader sr = new StreamReader(endpointsFile);
                var ends = JObject.Parse(sr.ReadToEnd()).ToObject<Endpoints>();
                sr.Close();

                string path = httpContext.Request.RouteValues["path"]!.ToString()!;

                string auth = httpContext.Request.Headers["Authorization"]!.ToString()!;
                if (!auth.StartsWith("Bearer "))
                    throw new Exception("Invalid authentication");
                auth = auth.Substring(7);

                foreach (var end in ends!.endpoints)
                {
                    if (end.proxyUrl == path)
                    {
                        bool authOk = false;
                        foreach (var tok in end.tokens)
                        {
                            if (tok.id == auth)
                            {
                                authOk = true;
                                break;
                            }
                        }

                        if (!authOk)
                            throw new Exception("Unauthorized");

                        target = end;
                        break;
                    }
                }

                if (target == null)
                    throw new Exception("Invalid endpoint");

                if (target.password.StartsWith("plain:"))
                {
                    target.password = EncryptString(target.password.Substring(6));

                    StreamWriter sw = new StreamWriter(endpointsFile);
                    sw.Write(JObject.FromObject(ends).ToString(Newtonsoft.Json.Formatting.Indented));
                    sw.Close();
                }

                var intHandler = new HttpClientHandler();
                intHandler.Credentials = new NetworkCredential(target.login, DecryptString(target.password));

                var intClient = new HttpClient(intHandler);

                var intRequest = new HttpRequestMessage();
                intRequest.Method = HttpMethod.Post;
                intRequest.RequestUri = new Uri(target.internalUrl);

                var ms = new MemoryStream();
                await httpContext.Request.Body.CopyToAsync(ms);

                var reqContent = new ByteArrayContent(ms.ToArray());
                reqContent.Headers.Add("Content-Type", httpContext.Request.ContentType);
                intRequest.Content = reqContent;

                var intResponse = intClient.Send(intRequest);

                if (!target.return200inError)
                    httpContext.Response.StatusCode = Convert.ToInt32(intResponse.StatusCode);
                httpContext.Response.ContentType = intResponse.Content.Headers.ContentType!.ToString();

                ms.Close();
                ms = new MemoryStream();
                intResponse.Content.ReadAsStream().CopyTo(ms);
                await httpContext.Response.Body.WriteAsync(ms.ToArray());
                ms.Close();

            }
            catch (Exception ex)
            {
                if ((target == null) || (!target.return200inError))
                    httpContext.Response.StatusCode = 500;
                httpContext.Response.ContentType = "application/json";

                var res = new ErrorResponse(ex);
                await httpContext.Response.WriteAsync(JObject.FromObject(res).ToString(Newtonsoft.Json.Formatting.Indented));
            }
        }

        static string EncryptString(string value)
        {
            var sha = SHA256.Create();
            var shaKey = sha.ComputeHash(Encoding.UTF8.GetBytes(ENCRYPT_KEY));

            var aes = Aes.Create();
            aes.Key = shaKey;
            aes.IV = new byte[16];

            var aesVal = aes.EncryptEcb(Encoding.UTF8.GetBytes(value), PaddingMode.PKCS7);
            return Convert.ToBase64String(aesVal);
        }

        static string DecryptString(string value)
        {
            if (value == "")
                return "";

            var sha = SHA256.Create();
            var shaKey = sha.ComputeHash(Encoding.UTF8.GetBytes(ENCRYPT_KEY));

            var aes = Aes.Create();
            aes.Key = shaKey;
            aes.IV = new byte[16];

            var aesVal = aes.DecryptEcb(Convert.FromBase64String(value), PaddingMode.PKCS7);
            return Encoding.UTF8.GetString(aesVal);
        }
    }
}