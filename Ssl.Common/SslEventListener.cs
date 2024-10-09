using System.Diagnostics.Tracing;
using System.Reflection;
using System.Text.Json;

namespace Ssl.Common;

public class SslEventListener : EventListener
{
    public void EnableLogs()
    {
        var netSecurityTelemetry = Assembly.Load("System.Net.Security").GetType("System.Net.Security.NetSecurityTelemetry")!;
        var netSecurityTelemetryLog = netSecurityTelemetry.GetField("Log", BindingFlags.Public | BindingFlags.Static)!.GetValue(null);

        var netEventSource = Assembly.Load("System.Net.Security").GetType("System.Net.NetEventSource")!;
        var netEventSourceLog = netEventSource.GetField("Log", BindingFlags.Public | BindingFlags.Static)!.GetValue(null);

        EnableEvents((EventSource)netSecurityTelemetryLog!, EventLevel.LogAlways);
        EnableEvents((EventSource)netEventSourceLog!, EventLevel.LogAlways);
    }
    protected override void OnEventWritten(EventWrittenEventArgs eventData)
    {
        if (eventData.EventSource.Name == "System.Net.Security")
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}]: {JsonSerializer.Serialize(eventData)}");
        if (eventData.EventSource.Name == "Private.InternalDiagnostics.System.Net.Security")
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}]: {JsonSerializer.Serialize(eventData)}");
    }
}