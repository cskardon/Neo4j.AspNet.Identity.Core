namespace Neo4j.AspNet.Identity.Core
{
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.DependencyInjection;

    public static class IdentityBuilderExtensions
    {
        public static IdentityBuilder UseNeo4jDataStoreAdapter(this IdentityBuilder builder)
        {
            return builder
                .AddNeo4jUserStore()
                .AddNeo4jRoleStore();
        }

        private static IdentityBuilder AddNeo4jUserStore(this IdentityBuilder builder)
        {
            var userStoreType = typeof(Neo4jUserStore<>).MakeGenericType(builder.UserType);
            builder.Services.AddScoped(
                typeof(IUserStore<>).MakeGenericType(builder.UserType),
                userStoreType);

            return builder;
        }

        private static IdentityBuilder AddNeo4jRoleStore(this IdentityBuilder builder)
        {
            var roleStoreType = typeof(Neo4jRoleStore<>).MakeGenericType(builder.RoleType);

            builder.Services.AddScoped(
                typeof(IRoleStore<>).MakeGenericType(builder.RoleType),
                roleStoreType
            );

            return builder;
        }
    }
}