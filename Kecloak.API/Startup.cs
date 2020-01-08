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
            services.AddAuthorization(auth =>
            {   
                auth.AddPolicy("ADM", new AuthorizationPolicyBuilder()
                    .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme‌​)
                    .RequireAuthenticatedUser()
                    .Build());
            });

            services.AddMvc(setupOptions =>
            {
                var authorizationPolicy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme)
                    .RequireAuthenticatedUser()
                    .Build();
                setupOptions.Filters.Add(new AuthorizeFilter(authorizationPolicy));
            });


            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(bearerOptions =>
            {
                bearerOptions.Authority = Configuration["Jwt:Authority"];
                //   bearerOptions.Audience = Configuration["Jwt:Audience"];
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
                    }
                };
            });
        }
    }
}
