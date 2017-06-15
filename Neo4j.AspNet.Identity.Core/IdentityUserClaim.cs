namespace Neo4j.AspNet.Identity.Core
{
    using System.Security.Claims;

    public class IdentityUserClaim
    {

        public virtual string Id { get; set; }

        public virtual string UserId { get; set; }

        public virtual string ClaimType { get; set; }

        public virtual string ClaimValue { get; set; }

        public Claim ToClaim()
        {
            return new Claim(ClaimType, ClaimValue);
        }
    }
}