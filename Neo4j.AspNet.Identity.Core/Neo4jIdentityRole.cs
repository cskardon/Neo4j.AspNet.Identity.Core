namespace Neo4j.AspNet.Identity.Core
{
    using System;
    using System.Collections.Generic;

    public class Neo4jIdentityRole
    {
        private readonly List<SimplifiedClaim> _claims;

        public Neo4jIdentityRole()
        {
            _claims = new List<SimplifiedClaim>();
            Id = Guid.NewGuid().ToString();
        }


        public string Id { get; internal set; }
        public string Name { get; set; }
        public string NormalizedName { get; set; }

        public IEnumerable<SimplifiedClaim> Claims
        {
            get => _claims;
            internal set
            {
                if (value != null) _claims.AddRange(value);
            }
        }

        internal void AddClaim(SimplifiedClaim claim)
        {
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            _claims.Add(claim);
        }

        internal void RemoveClaim(SimplifiedClaim claim)
        {
            _claims.Remove(claim);
        }

        public static implicit operator Neo4jIdentityRole(string input)
        {
            return input == null ? null : new Neo4jIdentityRole {Name = input};
        }
    }
}