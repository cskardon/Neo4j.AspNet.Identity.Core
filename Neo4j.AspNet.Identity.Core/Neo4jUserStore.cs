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

    public class Neo4jUserStore<TUser>
        : BaseUserStore,
            IUserLoginStore<TUser>,
            IUserPasswordStore<TUser>,
            IUserClaimStore<TUser>,
            IUserSecurityStampStore<TUser>,
            IUserTwoFactorStore<TUser>,
            IUserEmailStore<TUser>,
            IUserLockoutStore<TUser>,
            IUserPhoneNumberStore<TUser>
        where TUser : IdentityUser, new()
    {
        public Neo4jUserStore(IGraphClient client,
            string userLabel = null,
            string claimLabel = null,
            string loginLabel = null,
            string roleLabel = null, 
            IdentityErrorDescriber errorDescriber = null) : base(client, errorDescriber)
        {
            UserLabel = string.IsNullOrWhiteSpace(userLabel) ? ApplicationUser.Labels : userLabel;
            ClaimLabel = string.IsNullOrWhiteSpace(claimLabel) ? "Claim" : claimLabel;
            RoleLabel = string.IsNullOrWhiteSpace(roleLabel) ? "Role" : roleLabel;
            LoginLabel = string.IsNullOrWhiteSpace(loginLabel) ? "Login" : loginLabel;
        }

        private string UserLabel { get; }
        private string ClaimLabel { get; }
        private string LoginLabel { get; }
        private string RoleLabel { get; }

        

        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.UserName);
        }

        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            Throw.ArgumentException.IfNullOrWhiteSpace(userName, nameof(userName));
            ThrowIfDisposed();

            user.UserName = userName;
            return Task.CompletedTask;
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.NormalizedUserName);
        }

        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            user.NormalizedUserName = normalizedName;

            return Task.CompletedTask;
        }

        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            if (string.IsNullOrWhiteSpace(user.Id))
                user.Id = Guid.NewGuid().ToString();

            var query = new CypherFluentQuery(GraphClient)
                .Create($"(:{UserLabel} {{user}})")
                .WithParam("user", user);

            await query.ExecuteWithoutResultsAsync();

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            var query = UserMatch()
                .Where((TUser u) => u.Id == user.Id)
                .Set("u = {userParam}")
                .WithParam("userParam", user)
                .With("u").OptionalMatch($"(u)-[:{Relationship.HasClaim}]->(c:{ClaimLabel})").DetachDelete("c")
                .With("u").OptionalMatch($"(u)-[:{Relationship.HasLogin}]->(l:{LoginLabel})").DetachDelete("l")
                .With("u").OptionalMatch($"(u)-[:{Relationship.InRole}]->(r:{RoleLabel})").DetachDelete("r")
                .With("u").OptionalMatch($"(u)-[:{Relationship.IsLockedOut}]->(lo:{LockoutInfo.Label})").DetachDelete("lo");

            query = AddClaims(query, user.Claims);
            query = AddLogins(query, user.Logins);
            query = AddRoles(query, user.Roles);
            query = AddLockout(query, user.Lockout);

            await query.ExecuteWithoutResultsAsync();
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            var query = UserMatch()
                .Where((TUser u) => u.Id == user.Id)
                .DetachDelete("u");

            await query.ExecuteWithoutResultsAsync();
            return IdentityResult.Success;
        }

        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNullOrWhiteSpace(userId, nameof(userId));
            ThrowIfDisposed();

            var query = UserMatch()
                .Where((TUser u) => u.Id == userId)
                .OptionalMatch($"(u)-[:{Relationship.HasLogin}]->(l:{LoginLabel})")
                .OptionalMatch($"(u)-[:{Relationship.HasClaim}]->(c:{ClaimLabel})")
                .OptionalMatch($"(u)-[:{Relationship.InRole}]->(r:{RoleLabel})")
                .OptionalMatch($"(u)-[:{Relationship.IsLockedOut}]->(lo:{LockoutInfo.Label})")
                .Return((u, c, l, r, lo) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<Neo4jUserLoginInfo>(),
                    Claims = c.CollectAs<SimplifiedClaim>(),
                    Roles = r.CollectAs<Neo4jIdentityRole>(),
                    Lockout = r.CollectAs<LockoutInfo>()
                });

            var user = (await query.ResultsAsync).SingleOrDefault();

            return user?.Combine();
        }

        public async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNullOrWhiteSpace(normalizedUserName, nameof(normalizedUserName));
            ThrowIfDisposed();

            normalizedUserName = normalizedUserName.ToLowerInvariant().Trim();

            var query = UserMatch()
                .Where((TUser u) => u.UserName == normalizedUserName)
                .OptionalMatch($"(u)-[:{Relationship.HasLogin}]->(l:{LoginLabel})")
                .OptionalMatch($"(u)-[:{Relationship.HasClaim}]->(c:{ClaimLabel})")
                .OptionalMatch($"(u)-[:{Relationship.InRole}]->(r:{RoleLabel})")
                .OptionalMatch($"(u)-[:{Relationship.IsLockedOut}]->(lo:{LockoutInfo.Label})")
                .Return((u, c, l, r, lo) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<Neo4jUserLoginInfo>(),
                    Claims = c.CollectAs<SimplifiedClaim>(),
                    Roles = r.CollectAs<Neo4jIdentityRole>(),
                    Lockout = r.CollectAs<LockoutInfo>()
                });

            var results = await query.ResultsAsync;
            var findUserResult = results.SingleOrDefault();
            return findUserResult?.Combine();
        }



        private ICypherFluentQuery AddClaims(ICypherFluentQuery query, IList<SimplifiedClaim> claims)
        {
            if (claims == null || claims.Count == 0)
                return query;

            for (var i = 0; i < claims.Count; i++)
            {
                var claimName = $"claim{i}";
                var claimParam = claims[i];
                query = query.With("u")
                    .Create($"(u)-[:{Relationship.HasClaim}]->(c{i}:{ClaimLabel} {{{claimName}}})")
                    .WithParam(claimName, claimParam);
            }
            return query;
        }

        private  ICypherFluentQuery AddRoles(ICypherFluentQuery query, ICollection<Neo4jIdentityRole> roles)
        {
            if (roles == null || roles.Count == 0)
                return query;

            query = query.With("u")
                .Unwind(roles, "role")
                .Match($"(r:{RoleLabel} {{NormalizedName: role.NormalizedName}})")
                .With("u,r")
                .Create($"(u)-[:{Relationship.InRole}]->(r)");
            
            return query;
        }

        private ICypherFluentQuery AddLockout(ICypherFluentQuery query, LockoutInfo lockoutInfo)
        {
            if (lockoutInfo == null)
                return query;

            query = query.With("u")
                .Create($"(u)-[:{Relationship.IsLockedOut}]->(:{LockoutInfo.Label} {{lockoutParam}})")
                .WithParam("lockoutParam", lockoutInfo);
            return query;
        }

        private  ICypherFluentQuery AddLogins(ICypherFluentQuery query, IList<UserLoginInfo> logins)
        {
            if (logins == null || logins.Count == 0)
                return query;

            for (var i = 0; i < logins.Count; i++)
            {
                var loginName = $"login{i}";
                var loginParam = new InternalLoginProvider(logins[i]);
                query = query.With("u")
                    .Create($"(u)-[:{Relationship.HasLogin}]->(l{i}:{LoginLabel} {{{loginName}}})")
                    .WithParam(loginName, loginParam);
            }
            return query;
        }

        /// <summary>
        /// This exists, as the default <see cref="UserLoginInfo"/> contains circular references that Json.NET doesn't like.
        /// Only used for updates, serializing back is fine.
        /// </summary>
        private class InternalLoginProvider
        {
            public InternalLoginProvider(UserLoginInfo info)
            {
                LoginProvider = info.LoginProvider;
                ProviderDisplayName = info.ProviderDisplayName;
                ProviderKey = info.ProviderKey;
            }

            private string LoginProvider { get; set; }
            private string ProviderDisplayName { get; set; }
            private string ProviderKey { get; set; }
        }

        /// <summary>
        ///     Gets: <c>MATCH (<paramref name="userIdentifier" />:<see cref="UserLabel" />)</c>
        /// </summary>
        private ICypherFluentQuery UserMatch(string userIdentifier = "u")
        {
            return new CypherFluentQuery(GraphClient).Match($"({userIdentifier}:{UserLabel})");
        }

        #region Implementation of IUserLoginStore<TUser>

        public Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            Throw.ArgumentException.IfNull(login, nameof(login));
            ThrowIfDisposed();

            user.Logins.Add(login);

            return Task.CompletedTask;
        }

        public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            Throw.ArgumentException.IfNull(loginProvider, nameof(loginProvider));
            Throw.ArgumentException.IfNull(providerKey, nameof(providerKey));
            ThrowIfDisposed();

            var login = user.Logins.SingleOrDefault(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey);
            user.Logins.Remove(login);
            return Task.CompletedTask;
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult<IList<UserLoginInfo>>(user.Logins.ToList());
        }

        public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(loginProvider, nameof(loginProvider));
            Throw.ArgumentException.IfNull(providerKey, nameof(providerKey));
            ThrowIfDisposed();

            var query = new CypherFluentQuery(GraphClient)
                .Match($"(l:{LoginLabel})<-[:{Relationship.HasLogin}]-(u:{UserLabel})")
                .Where((UserLoginInfo l) => l.LoginProvider == loginProvider)
                .AndWhere((UserLoginInfo l) => l.ProviderKey == providerKey)
                .Return(u => u.As<TUser>());

            var results = await query.ResultsAsync;
            return results.SingleOrDefault();
        }

        #endregion

        #region Implementation of IUserPasswordStore<TUser>

        public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            Throw.ArgumentException.IfNullOrWhiteSpace(passwordHash, nameof(passwordHash));
            ThrowIfDisposed();

            user.PasswordHash = passwordHash;
            return Task.CompletedTask;
        }

        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(!string.IsNullOrWhiteSpace(user.PasswordHash));
        }

        #endregion

        #region Implementation of IUserClaimStore<TUser>

        public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult<IList<Claim>>(user.Claims.Select(c => c.ToClaim()).ToList());
        }

        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            foreach (var claim in claims)
                user.AddClaim(claim);

            return Task.CompletedTask;
        }

        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            Throw.ArgumentException.IfNull(newClaim, nameof(newClaim));
            Throw.ArgumentException.IfNull(claim, nameof(claim));
            ThrowIfDisposed();

            user.RemoveClaim(claim);
            user.AddClaim(claim);
            
            return Task.CompletedTask;
        }

        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            foreach (var claim in claims)
                user.RemoveClaim(claim);

            return Task.CompletedTask;
        }

        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(claim, nameof(claim));
            ThrowIfDisposed();

            var query = new CypherFluentQuery(GraphClient)
                .Match($"(c:{ClaimLabel})<-[:{Relationship.HasClaim}]-(u:{UserLabel})")
                .Where((SimplifiedClaim c) => c.Type == claim.Type)
                .AndWhere((SimplifiedClaim c) => c.Value == claim.Value)
                .Return(u => u.As<TUser>());

            var result = await query.ResultsAsync;
            return result.ToList();
        }

        #endregion

        #region Implementation of IUserSecurityStampStore<TUser>

        public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            Throw.ArgumentException.IfNullOrWhiteSpace(stamp, nameof(stamp));
            ThrowIfDisposed();

            user.SecurityStamp = stamp;
            return Task.CompletedTask;
        }

        public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.SecurityStamp);
        }

        #endregion

        #region Implementation of IUserTwoFactorStore<TUser>

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            user.UsesTwoFactorAuthentication = enabled;
            return Task.CompletedTask;
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.UsesTwoFactorAuthentication);
        }

        #endregion

        #region Implementation of IUserEmailStore<TUser>

        public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            Throw.ArgumentException.IfNullOrWhiteSpace(email, nameof(email));
            ThrowIfDisposed();

            user.Email = email;
            return Task.CompletedTask;
        }

        public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            user.EmailConfirmed = confirmed;
            return Task.CompletedTask;
        }

        public async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNullOrWhiteSpace(normalizedEmail, nameof(normalizedEmail));
            ThrowIfDisposed();

            normalizedEmail = normalizedEmail.Trim().ToUpperInvariant();

            var query = new CypherFluentQuery(GraphClient)
                .Match($"(u:{UserLabel})")
                .Where((TUser u) => u.NormalizedEmail == normalizedEmail)
                .Return(u => u.As<TUser>());

            return (await query.ResultsAsync).SingleOrDefault();
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.NormalizedEmail);
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            Throw.ArgumentException.IfNullOrWhiteSpace(normalizedEmail, nameof(normalizedEmail));
            ThrowIfDisposed();

            user.NormalizedEmail = normalizedEmail;
            return Task.CompletedTask;
        }

        #endregion

        #region Implementation of IUserLockoutStore<TUser>

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.Lockout?.EndDate);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            if(user.Lockout == null)
                user.Lockout = new LockoutInfo();

            user.Lockout.EndDate = lockoutEnd;
            return Task.CompletedTask;
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            if (user.Lockout == null)
                user.Lockout = new LockoutInfo();

            user.Lockout.AccessFailedCount += 1;
            return Task.FromResult(user.Lockout.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            if (user.Lockout == null)
                user.Lockout = new LockoutInfo();

            user.Lockout.AccessFailedCount = 0;
            return Task.CompletedTask;
        }

        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            if (user.Lockout == null)
                user.Lockout = new LockoutInfo();

            return Task.FromResult(user.Lockout.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.Lockout?.Enabled  ?? false);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            if (user.Lockout == null)
                user.Lockout = new LockoutInfo();

            user.Lockout.Enabled = enabled;
            return Task.CompletedTask;
        }

        #endregion

        #region Implementation of IUserPhoneNumberStore<TUser>

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            Throw.ArgumentException.IfNullOrWhiteSpace(phoneNumber, nameof(phoneNumber));
            ThrowIfDisposed();

            user.PhoneNumber = phoneNumber;
            return Task.CompletedTask;
        }

        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Throw.ArgumentException.IfNull(user, nameof(user));
            ThrowIfDisposed();

            user.PhoneNumberConfirmed = confirmed;
            return Task.CompletedTask;
        }

        #endregion
    }


    #region Internal Classes for Serialization

    internal class FindUserResult<T>
        where T : IdentityUser, new()
    {
        public T User { private get; set; }
        public IEnumerable<Neo4jUserLoginInfo> Logins { private get; set; }
        public IEnumerable<SimplifiedClaim> Claims { private get; set; }
        public IEnumerable<LockoutInfo> Lockout { private get; set; }

        public IEnumerable<Neo4jIdentityRole> Roles { private get; set; }

        public T Combine()
        {
            var output = User;
            if (Logins != null)
                output.Logins = new List<UserLoginInfo>(Logins.Select(l => l.ToUserLoginInfo()));
            if (Claims != null)
                output.Claims = new List<SimplifiedClaim>(Claims);
            if (Lockout != null)
                output.Lockout = Lockout.SingleOrDefault();
            if(Roles != null)
                output.Roles = new List<Neo4jIdentityRole>(Roles);
            
            return output;
        }
    }

    // ReSharper disable once ClassNeverInstantiated.Local
    internal class Neo4jUserLoginInfo
    {
        /// <summary>
        ///     The display name for this user supplied by the provider.
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        ///     Provider for the linked login, i.e. Facebook, Google, etc.
        /// </summary>
        public string LoginProvider { get; set; }

        /// <summary>
        ///     User specific key for the login provider
        /// </summary>
        public string ProviderKey { get; set; }

        public UserLoginInfo ToUserLoginInfo()
        {
            return new UserLoginInfo(LoginProvider, ProviderKey, DisplayName);
        }
    }

    #endregion Internal Classes for Serialization
}