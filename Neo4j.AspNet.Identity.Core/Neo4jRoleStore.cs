namespace Neo4j.AspNet.Identity.Core
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Identity;
    using Neo4jClient;
    using Neo4jClient.Cypher;

    public class Neo4jRoleStore<TRole>
        : BaseUserStore, IQueryableRoleStore<TRole>, IRoleClaimStore<TRole>
        where TRole : Neo4jIdentityRole

    {
        private string RoleLabel { get; }
        public Neo4jRoleStore(IGraphClient graphClient, string roleLabel = null, IdentityErrorDescriber errorDescriber = null) : base(graphClient, errorDescriber)
        {
            RoleLabel = string.IsNullOrWhiteSpace(roleLabel) ? "Role" : roleLabel;
        }

        #region Implementation of IRoleStore<TRole>

        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            ThrowIfDisposed();

            var query = new CypherFluentQuery(GraphClient).Create($"(:{RoleLabel} {{roleParam}})").WithParam("roleParam", role);
            await query.ExecuteWithoutResultsAsync();
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            ThrowIfDisposed();

            var query = new CypherFluentQuery(GraphClient)
                .Match($"(r:{RoleLabel})")
                .Where((TRole r) => r.Id == role.Id)
                .Set("r = {roleParam}")
                .WithParam("roleParam", role);

            await query.ExecuteWithoutResultsAsync();
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            ThrowIfDisposed();

            var query = new CypherFluentQuery(GraphClient)
                .Match($"(r:{RoleLabel})")
                .Where((TRole r) => r.Id == role.Id)
                .DetachDelete("r");

            await query.ExecuteWithoutResultsAsync();
            return IdentityResult.Success;
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            ThrowIfDisposed();

            return Task.FromResult(role.Id);
        }

        public Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            ThrowIfDisposed();

            return Task.FromResult(role.Name);
        }

        public Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            Throw.ArgumentException.IfNullOrWhiteSpace(roleName, nameof(roleName));
            ThrowIfDisposed();

            role.Name = roleName;
            return Task.CompletedTask;
        }

        public Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            ThrowIfDisposed();

            return Task.FromResult(role.NormalizedName);
        }

        public Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            Throw.ArgumentException.IfNullOrWhiteSpace(normalizedName, nameof(normalizedName));
            ThrowIfDisposed();

            role.Name = normalizedName;
            return Task.CompletedTask;
        }

        public async Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(roleId, nameof(roleId));
            ThrowIfDisposed();

            var query = new CypherFluentQuery(GraphClient)
                .Match($"(r:{RoleLabel})")
                .Where((TRole r) => r.Id == roleId)
                .Return(r => r.As<TRole>());

            return (await query.ResultsAsync).SingleOrDefault();
        }

        public async Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(normalizedRoleName, nameof(normalizedRoleName));
            ThrowIfDisposed();

            var query = new CypherFluentQuery(GraphClient)
                .Match($"(r:{RoleLabel})")
                .Where((TRole r) => r.NormalizedName == normalizedRoleName)
                .Return(r => r.As<TRole>());

            return (await query.ResultsAsync).SingleOrDefault();
        }

        #endregion

        #region Implementation of IQueryableRoleStore<TRole>

        public IQueryable<TRole> Roles => throw new NotSupportedException();

        #endregion

        #region Implementation of IRoleClaimStore<TRole>

        public Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            ThrowIfDisposed();

            return Task.FromResult<IList<Claim>>(role.Claims.Select(c => c.ToClaim()).ToList());
        }

        public Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            ThrowIfDisposed();

            role.AddClaim(claim);
            return Task.CompletedTask;
        }

        public Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = new CancellationToken())
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(role, nameof(role));
            ThrowIfDisposed();

           role.RemoveClaim(claim);
            return Task.CompletedTask;
        }

        #endregion
    }
}