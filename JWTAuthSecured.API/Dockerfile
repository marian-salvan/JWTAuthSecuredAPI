#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["JWTAuthSecured.API/JWTAuthSecured.API.csproj", "JWTAuthSecured.API/"]
COPY ["JWTAuthSecured.Data/JWTAuthSecured.Data.csproj", "JWTAuthSecured.Data/"]
COPY ["JWTAuthSecured.Core/JWTAuthSecured.Core.csproj", "JWTAuthSecured.Core/"]
RUN dotnet restore "JWTAuthSecured.API/JWTAuthSecured.API.csproj"
COPY . .
WORKDIR "/src/JWTAuthSecured.API"
RUN dotnet build "JWTAuthSecured.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "JWTAuthSecured.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "JWTAuthSecured.API.dll"]