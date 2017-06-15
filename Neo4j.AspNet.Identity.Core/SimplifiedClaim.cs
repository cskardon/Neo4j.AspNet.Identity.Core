namespace Neo4j.AspNet.Identity.Core
{
    using System;
    using System.Security.Claims;

    public class SimplifiedClaim : IEquatable<SimplifiedClaim>, IEquatable<Claim>
    {
        public string Type { get; set; }
        public string Value { get; set; }

        public Claim ToClaim()
        {
            return new Claim(Type, Value);
        }

        public bool Equals(Claim other)
        {
            return Type == other.Type && Value == other.Value;
        }

        public bool Equals(SimplifiedClaim other)
        {
            return Type == other.Type && Value == other.Value;
        }

        public static implicit operator SimplifiedClaim(Claim original)
        {
            return new SimplifiedClaim {Type = original.Type, Value = original.Value};
        }

        public static implicit operator Claim(SimplifiedClaim simplified)
        {
            return new Claim(simplified.Type, simplified.Value);
        }
    }
}