using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Step3_WebApi_Jwt.Logger
{
    public static class InMemoryLoggerExtensions
    {
        public static ILoggingBuilder AddInMemoryLogger (this ILoggingBuilder builder)
        {
            builder.Services.AddSingleton<ILoggerProvider, InMemoryLoggerProvider>();
            return builder;
        }
    }
}
