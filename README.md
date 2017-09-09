# Neo4j.AspNet.Identity.Core
A NetStandard implementation of Neo4j.AspNet.Identity

## No Tests or Nuget (Yet) !!

Both coming VERY soon

## How to use

1. Create a new ASP .NET Core project - choosing the Individual User Accounts authentication type
2. Add this project to your solution
3. Reference it from the 'web project'
4. Remove all the EntityFramework nuget packages: (where we're going we don't need the EntityFramework)
    * Microsoft.AspNetCore.Diagnostics.EntityFrameworkCore
    * Microsoft.AspNetCore.Identity.EntityFrameworkCore
    * Microsoft.EntityFrameworkCore.Design
    * Microsoft.EntityFrameworkCore.SqlServer
    * Microsoft.EntityFrameworkCore.SqlServer.Design
    * Microsoft.EntityFrameworkCore.Tools
5. Delete:
    * Data folder (and all in there)
6. Remove 'using' statements (easiest is a Find/Replace [CTRL+SHIFT+H]) wherever they are that look like:
    * `using Microsoft.AspNetCore.Identity.EntityFrameworkCore;`
    * `using AspNetCoreIdentityChanging.Data;`
7. In `startup.cs` add this method:
    ```
    private static IGraphClient GetGraphClient()
    {
        var graphClient = new GraphClient(new Uri("your uri"), "user", "pass");
        graphClient.Connect();
        return graphClient;
    }
    ```
8. Change the `ConfigureServices` method to be:
   ```
   public void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton(GetGraphClient());
        services.AddIdentity<ApplicationUser, Neo4jIdentityRole>()
            .UseNeo4jDataStoreAdapter()
            .AddDefaultTokenProviders();

        services.AddMvc();

        // Add application services.
        services.AddTransient<IEmailSender, AuthMessageSender>();
        services.AddTransient<ISmsSender, AuthMessageSender>();
    }
   ```
9. Remove the `app.UseDatabaseErrorPage()` line in the `Configure(...)` method

10. Remove the `ApplicationUser.cs` file in the `Models` folder, as this will conflict with the one declared within this package.

Now you should be able to start, register and login!


### Notes
Built based on [Neo4j.AspNet.Identity](https://github.com/DotNet4Neo4j/Neo4j.AspNet.Identity) with changes influenced (and indeed in some cases copied) from [Writing An ASP.NET Core Identity Storage Provider From Scratch With RavenDB](http://www.elemarjr.com/en/2017/05/writing-an-asp-net-core-identity-storage-provider-from-scratch-with-ravendb/) by [ElmarJR](https://github.com/ElemarJR).

