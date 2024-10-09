using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Ssl.Common;

var eventListener = new SslEventListener();
eventListener.EnableLogs();

var certificate = new X509Certificate2("/usr/local/share/ca-certificates/cert.pfx", "987654321");

while (true)
{
    using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
    await socket.ConnectAsync("ssl-server", 12345);
    await using var networkStream = new NetworkStream(socket);
    await using var sslStream = new SslStream(networkStream, false);
    
    var sslOptions = new SslClientAuthenticationOptions
    {
        EnabledSslProtocols = SslProtocols.Tls12,
        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        RemoteCertificateValidationCallback = (_,_,_,_) => true,
        TargetHost = "ssl-server",
        AllowRenegotiation = true,
        LocalCertificateSelectionCallback = (_,_,_,_,_) => certificate,
        CertificateChainPolicy = new X509ChainPolicy()
        {
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
            VerificationFlags = X509VerificationFlags.AllFlags,
        }
    };
    // this lines fix the problem, but its a big crutch
    // typeof(SslStream).GetField("_remoteCertificate", BindingFlags.NonPublic | BindingFlags.Instance).SetValue(sslStream,
    //     new X509Certificate2("/usr/local/share/ca-certificates/cert.pfx", "987654321"));
    var watch = new Stopwatch();
    watch.Start();
    await sslStream.AuthenticateAsClientAsync(sslOptions);
    watch.Stop();
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}]: {watch.ElapsedMilliseconds.ToString()}");
    await Task.Delay(15000);
}