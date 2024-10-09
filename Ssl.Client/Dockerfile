FROM mcr.microsoft.com/dotnet/runtime:8.0-alpine AS base
USER root
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["Ssl.Client/Ssl.Client.csproj", "Ssl.Client/"]
COPY ["Ssl.Common/Ssl.Common.csproj", "Ssl.Common/"]
RUN dotnet restore "Ssl.Client/Ssl.Client.csproj"
COPY . .
WORKDIR "/src/Ssl.Client"
RUN dotnet build "Ssl.Client.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "Ssl.Client.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
COPY cert.pfx /usr/local/share/ca-certificates/cert.pfx
COPY cert.crt /usr/local/share/ca-certificates/cert.crt
COPY cert.pem /usr/local/share/ca-certificates/cert.pem
RUN apk add ca-certificates
RUN update-ca-certificates
ENTRYPOINT ["dotnet", "Ssl.Client.dll"]
