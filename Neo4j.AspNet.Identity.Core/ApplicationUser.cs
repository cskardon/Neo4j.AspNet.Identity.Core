using System.Text;

namespace Neo4j.AspNet.Identity.Core
{
    /// <summary>
    /// This is the main User Object for the Identity. Extend it to add extra features.
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        /// <summary>
        /// Gets the default labels used (User) for an <see cref="ApplicationUser"/>.
        /// </summary>
        public static string Labels => "User";

    }
}
