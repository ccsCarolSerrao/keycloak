using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;
using System.Security.Cryptography.X509Certificates;
using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Threading.Tasks;

namespace Kecloak.API
{
    public class Startup
    {
        public Startup(IHostingEnvironment env, IConfiguration configuration)
        {
            Configuration = configuration;
            Environment = env;
        }

        public IConfiguration Configuration { get; }
        public IHostingEnvironment Environment { get; }


        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = true;
            services.AddControllers();
            ConfigureAuthentication(services);
            ConfigureAuthorization(services);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpMethodOverride();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }

        private void ConfigureAuthentication(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(bearerOptions =>
            {
                bearerOptions.Authority = Configuration["Jwt:Authority"];
                bearerOptions.Audience = Configuration["Jwt:Audience"];
                bearerOptions.SaveToken = true;
                bearerOptions.IncludeErrorDetails = true;
                if (Environment.IsDevelopment())
                {
                    bearerOptions.RequireHttpsMetadata = false;
                }

                var listAudiences = new List<string>();
                listAudiences.Add(Configuration["Jwt:Audience"]);

                bearerOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    SaveSigninToken = true,
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidIssuer = Configuration["Jwt:Authority"],
                    ValidateAudience = true,
                    ValidAudiences = listAudiences,
                    ValidateLifetime = true
                };

                bearerOptions.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        context.NoResult();
                        context.Response.StatusCode = 401;
                        context.Response.ContentType = "text/plain";

                        var errorMessage = context.Exception switch
                        {
                            SecurityTokenExpiredException _ => "Expired token.",
                            SecurityTokenNotYetValidException _ => "Token not yet valid.",
                            SecurityTokenInvalidLifetimeException _ => "Invalid token lifetime.",
                            SecurityTokenNoExpirationException _ => "Missing token expiration.",
                            SecurityTokenSignatureKeyNotFoundException _ => "Invalid token. Key not found.",
                            _ => "An error occured processing your authentication."
                        };

                        if (Environment.IsDevelopment())
                        {
                            errorMessage += " - " + context.Exception.ToString();
                        }

                        return context.Response.WriteAsync(errorMessage);
                    },

                    OnTokenValidated = context =>
                    {
                        var resourceAccess = JObject.Parse(context.Principal.FindFirstValue("resource_access"));
                        var clientRoles = resourceAccess[Configuration["Jwt:Audience"]]["roles"];
                        var claimsIdentity = context.Principal.Identity as ClaimsIdentity;
                        if (claimsIdentity != null)
                        {
                            foreach (var clientRole in clientRoles)
                            {
                                claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, clientRole.ToString()));
                            }
                        }
                        return Task.CompletedTask;
                    }
                };

            });

        }

        private void ConfigureAuthorization(IServiceCollection services)
        {
            services.AddAuthorization(auth =>
           {
               auth.DefaultPolicy = new AuthorizationPolicyBuilder()
                   .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme‌​)
                   .RequireAuthenticatedUser()
                   .Build();
           });
        }
    }
}
