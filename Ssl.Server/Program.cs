using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Ssl.Common;

var eventListener = new SslEventListener();
eventListener.EnableLogs();

var listener = new TcpListener(IPAddress.Any, 12345);
listener.Start();

var certificate = new X509Certificate2("/usr/local/share/ca-certificates/cert.pfx", "987654321");

while (true)
{
    try
    {
        var client = await listener.AcceptTcpClientAsync();

        await using var networkStream = client.GetStream();
        await using var sslStream = new SslStream(networkStream, false);

        await sslStream.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12, false);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error: {ex.Message}");
    }
}