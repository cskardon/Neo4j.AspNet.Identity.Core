namespace Neo4j.AspNet.Identity.Core
{
    /// <summary>Consts for the Relationships used within the Identity.</summary>
    internal static class Relationship
    {
        /// <summary>Relationship representing whether a user has another Login - <c>HAS_LOGIN</c></summary>
        /// <remarks><c>(User)-[:HAS_LOGIN]->(Login)</c></remarks>
        public const string HasLogin = "HAS_LOGIN";

        /// <summary>Relationship representing whether a user has a claim - <c>HAS_CLAIM</c></summary>
        /// <remarks><c>(User)-[:HAS_CLAIM]->(Login)</c></remarks>
        public const string HasClaim = "HAS_CLAIM";

        /// <summary>Relationship representing whether a user has a Role - <c>IN_ROLE</c></summary>
        /// <remarks><c>(User)-[:IN_ROLE]->(Role)</c></remarks>
        public const string InRole = "IN_ROLE";

        /// <summary>Relationship representing whether a user has been locked out - <c>IS_LOCKED_OUT</c></summary>
        /// <remarks><c>(User)-[:IS_LOCKED_OUT]->(Lockout)</c></remarks>
        public const string IsLockedOut = "IS_LOCKED_OUT";


    }
}