using System.ServiceProcess;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using Weldap;
using Weldap.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "Weldap");
builder.Logging.ClearProviders();
// Through NeverThrowingLoggerProvider: a full (do-not-overwrite) or broken event log must never make a log call
// throw -- one thrown from a fault handler would leave the host neither serving nor stopped.
builder.Logging.AddProvider(new NeverThrowingLoggerProvider(
    new EventLogLoggerProvider(new EventLogSettings { SourceName = EventLogAudit.Source })));
// The event-log provider defaults to Warning and up; our own Information lines (the integrity status at start)
// belong in the log too. The host's own chatter stays at Warning.
builder.Logging.AddFilter<NeverThrowingLoggerProvider>((category, level) =>
    level >= (category?.StartsWith("Microsoft.", StringComparison.Ordinal) == true ? LogLevel.Warning : LogLevel.Information));
builder.Services.AddHostedService<LoginWorker>();
await builder.Build().RunAsync().ConfigureAwait(false);

/// <summary>
/// Runs the pipe server and the hourly reconciler; one lock serialises all account changes.
///
/// Two ways to end, deliberately different:
/// - Refused at start (bad config or ACL, failed integrity check): fail closed and stay stopped, with a critical
///   event saying why. Nothing about that changes by itself, so restarting would only flood the log; fix the
///   setting and start the service again.
/// - Any fault once running: exit with a non-zero code. The MSI makes the service's failure actions apply to
///   non-crash failures too, so the Service Control Manager restarts it 5 s later. (Before, such a fault looked
///   like a normal stop, and WELDAP sign-in -- offline included -- stayed down until someone noticed.)
/// </summary>
internal sealed partial class LoginWorker(ILogger<LoginWorker> log, ILogger<PipeServer> pipeLog, IHostLifetime lifetime)
    : BackgroundService
{
    private readonly Lock _gate = new();
    private bool _refused;

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        try
        {
            await RunAsync(stop).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
        }
        catch (Exception ex) when (!_refused)
        {
            // The exit code first: whatever happens next, the SCM must see a failure and restart the service.
            Environment.ExitCode = 1;
            if (lifetime is ServiceBase service) service.ExitCode = 1; // reported to the SCM with SERVICE_STOPPED
            var type = ex.GetType().Name;
            LogFatal(log, type, ex.Message);
            throw;
        }
    }

    private async Task RunAsync(CancellationToken stop)
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
            _refused = true;
            throw;
        }

        var clock = new SystemClock();
        var audit = new EventLogAudit();
        var accounts = new LocalAccounts();
        var secrets = new RegistrySecretStore();
        var server = new ServerClient(settings);
        // One lock for every account change, shared by sign-ins and the reconciler; neither holds it while it waits
        // for the server, so concurrent sign-ins (several sessions) each get their own time budget.
        var handler = new LoginHandler(settings, server, accounts, secrets, audit, clock, new RateLimiter(clock), _gate);
        var reconciler = new Reconciler(settings, server, accounts, secrets, audit, clock);

        var pipe = new PipeServer(handler.Handle, pipeLog);
        var cleanup = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(LoginSettings.CleanupIntervalMinutes));
            do
            {
                try
                {
                    // The server is asked outside the lock (it can take ServerBudgetSeconds per batch); only the
                    // changes, made against the accounts as they are by then, hold up sign-ins.
                    if (reconciler.Read() is { } plan)
                    {
                        lock (_gate) reconciler.Apply(plan);
                    }
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

    // Explicit event ids (1500-1599, beside the audit events' 1000-1400): without them the generator picks a 32-bit
    // hash, the event log keeps its low 16 bits as the id and the rest as qualifiers, and Event Viewer then finds no
    // description for it -- the reason a service refused to start used to be unreadable there.
    [LoggerMessage(EventId = 1500, Level = LogLevel.Critical, Message = "WELDAP service refused to start: {Reason}")]
    private static partial void LogStartRefused(ILogger logger, string reason);

    [LoggerMessage(EventId = 1501, Level = LogLevel.Critical, Message = "WELDAP service stopping on a fault ({ExceptionType}: {Reason}); it will be restarted")]
    private static partial void LogFatal(ILogger logger, string exceptionType, string reason);

    [LoggerMessage(EventId = 1502, Level = LogLevel.Information, Message = "{Status}")]
    private static partial void LogIntegrity(ILogger logger, string status);

    [LoggerMessage(EventId = 1503, Level = LogLevel.Error, Message = "Cleanup failed: {Reason}")]
    private static partial void LogCleanupFailed(ILogger logger, string reason);
}

/// <summary>
/// Wraps a logger provider so no log call can throw. The event-log provider's WriteEntry throws when the log is
/// full and set not to overwrite (any interactive user can fill the Application log), and a log call inside a fault
/// handler that throws turns a clean restart into a hung, half-dead host.
/// </summary>
internal sealed class NeverThrowingLoggerProvider(ILoggerProvider inner) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new Logger(inner.CreateLogger(categoryName));

    public void Dispose() => inner.Dispose();

#pragma warning disable CA1031 // the whole point: a log write may fail; nothing that logs may fail because of it
    private sealed class Logger(ILogger inner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            try
            {
                return inner.BeginScope(state);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return null;
            }
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            try
            {
                return inner.IsEnabled(logLevel);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                return false;
            }
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            try
            {
                inner.Log(logLevel, eventId, state, exception, formatter);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
            }
        }
    }
#pragma warning restore CA1031
}
