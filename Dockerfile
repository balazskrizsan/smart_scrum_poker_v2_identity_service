FROM mcr.microsoft.com/dotnet/sdk:10.0 as build-env
WORKDIR /src
COPY IdentityService/*.csproj .
RUN dotnet restore
COPY IdentityService/ .
RUN dotnet publish -c Release -o /publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 as runtime
WORKDIR /publish
COPY --from=build-env /publish .
EXPOSE 80
ENTRYPOINT ["dotnet", "IdentityService.dll"]
