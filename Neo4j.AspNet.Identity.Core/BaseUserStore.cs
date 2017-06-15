namespace Neo4j.AspNet.Identity.Core
{
    using System;
    using Microsoft.AspNetCore.Identity;
    using Neo4jClient;

    public abstract class BaseUserStore : IDisposable
    {
        private bool _disposed;
        protected IGraphClient GraphClient { get; }
        protected IdentityErrorDescriber ErrorDescriber { get; }
        protected BaseUserStore(IGraphClient graphClient, IdentityErrorDescriber errorDescriber = null)
        {
            GraphClient = graphClient;
            ErrorDescriber = errorDescriber;
        }

        protected void Dispose(bool isDisposing)
        {
            _disposed = true;
        }

        protected void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}