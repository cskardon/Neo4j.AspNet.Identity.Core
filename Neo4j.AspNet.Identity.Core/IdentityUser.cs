namespace Neo4j.AspNet.Identity.Core
{
    using System;
    using System.Collections.Generic;
    using Microsoft.AspNetCore.Identity;
    using Newtonsoft.Json;

    public class IdentityUser
    {
        private string _userName;
        private DateTimeOffset _lastLoginDateUtc;

        public IdentityUser()
        {
            Claims = new List<SimplifiedClaim>();
            Roles = new List<Neo4jIdentityRole>();
            Logins = new List<UserLoginInfo>();
            CreateDateUtc = DateTimeOffset.UtcNow;
        }

        public IdentityUser(string username)
            : this()
        {
            Throw.ArgumentException.IfNullOrWhiteSpace(username, "username");
            UserName = username.ToLowerInvariant().Trim();
            NormalizedUserName = UserName;
        }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string DisplayName { get; set; }

        public DateTimeOffset LastLoginDateUtc
        {
            get => _lastLoginDateUtc;
            set
            {
                _lastLoginDateUtc = value;
                LastLoginDateUtcTicks = value.Ticks;
            }
        }

        public long LastLoginDateUtcTicks { get; private set; }

        public DateTimeOffset CreateDateUtc { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string PhoneNumber { get; set; }

        public bool PhoneNumberConfirmed { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual string PasswordHash { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual string SecurityStamp { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual string Email { get; set; }

        [JsonIgnore]
        public virtual List<Neo4jIdentityRole> Roles { get; set; }

        [JsonIgnore]
        public virtual List<SimplifiedClaim> Claims { get; set; }


//        public LockoutInfo Lockout { get; internal set; }
//        public PhoneInfo Phone { get; internal set; }


        [JsonIgnore]
        public virtual List<UserLoginInfo> Logins { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual string Id { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual string UserName
        {
            get => _userName;
            set
            {
                Throw.ArgumentException.IfNullOrWhiteSpace(value, "value");
                _userName = value.ToLowerInvariant().Trim();
            }
        }

        [JsonIgnore]
        public LockoutInfo Lockout { get; internal set; }

        public string NormalizedUserName { get; internal set; }
        public bool UsesTwoFactorAuthentication { get; internal set; }
        public bool EmailConfirmed { get; internal set; }
        public string NormalizedEmail { get; internal set; }

        internal void AddClaim(SimplifiedClaim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            Claims.Add(claim);
        }

//        internal void CleanUp()
//        {
//            if (Lockout != null && Lockout.AllPropertiesAreSetToDefaults)
//            {
//                Lockout = null;
//            }
//
//            if (Email != null && Email.AllPropertiesAreSetToDefaults)
//            {
//                Email = null;
//            }
//
//            if (Phone != null && Phone.AllPropertiesAreSetToDefaults)
//            {
//                Phone = null;
//            }
//        }

        internal void RemoveClaim(SimplifiedClaim claim)
        {
            Claims.Remove(claim);
        }

    }
}