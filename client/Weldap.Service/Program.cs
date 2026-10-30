using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Weldap;
using Weldap.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "Weldap");
builder.Logging.ClearProviders();
builder.Logging.AddEventLog(o => o.SourceName = EventLogAudit.Source);
builder.Services.AddHostedService<LoginWorker>();
await builder.Build().RunAsync().ConfigureAwait(false);

/// <summary>Runs the pipe server and the hourly reconciler; one lock serialises all account changes.</summary>
internal sealed partial class LoginWorker(ILogger<LoginWorker> log, ILogger<PipeServer> pipeLog) : BackgroundService
{
    private readonly Lock _gate = new();

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        LoginSettings settings;
        try
        {
            settings = RegistrySettings.Load();
            RegistrySecretStore.EnsureKey(); // SYSTEM-only, or refuse to run
            var integrity = IntegrityGuard.Verify(); // anti-tamper: the registered provider must be ours (throws if not)
            LogIntegrity(log, integrity);
        }
        catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // SR-10 / config error: refuse to run. The WELDAP tile then shows "service not available".
            LogStartRefused(log, ex.Message);
            throw;
        }

        var clock = new SystemClock();
        var audit = new EventLogAudit();
        var accounts = new LocalAccounts();
        var secrets = new RegistrySecretStore();
        var server = new ServerClient(settings);
        var handler = new LoginHandler(settings, server, accounts, secrets, audit, clock, new RateLimiter(clock));
        var reconciler = new Reconciler(settings, server, accounts, secrets, audit);

        var pipe = new PipeServer(request => { lock (_gate) return handler.Handle(request); }, pipeLog);
        var cleanup = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(LoginSettings.CleanupIntervalMinutes));
            do
            {
                try
                {
                    lock (_gate) reconciler.Run();
                }
                catch (LocalAccountException ex)
                {
                    LogCleanupFailed(log, ex.Message);
                }
#pragma warning disable CA1031 // the hourly cleanup must never take the service down with it
                catch (Exception ex) when (ex is not OutOfMemoryException and not OperationCanceledException)
                {
                    LogCleanupFailed(log, ex.GetType().Name);
                }
#pragma warning restore CA1031
            } while (await timer.WaitForNextTickAsync(stop).ConfigureAwait(false));
        }, stop);

        await pipe.RunAsync(stop).ConfigureAwait(false);
        try
        {
            await cleanup.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
    }

    [LoggerMessage(Level = LogLevel.Critical, Message = "WELDAP service refused to start: {Reason}")]
    private static partial void LogStartRefused(ILogger logger, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "{Status}")]
    private static partial void LogIntegrity(ILogger logger, string status);

    [LoggerMessage(Level = LogLevel.Error, Message = "Cleanup failed: {Reason}")]
    private static partial void LogCleanupFailed(ILogger logger, string reason);
}
