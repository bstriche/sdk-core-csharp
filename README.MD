# Introduction
This is the SDK Core API for all the C# SDK used in Mastercard. 
It provides some core functionality for all our SDKs.
It provide:
- exception handling
- security (OAUTH)
- crypt utilities
- message pump
- smart map (for inline request creation using fluent style api)

# Build
The project requires .NET Framework 4.6.1 and .NET Core 2.1 to be installed.

Build the project using Microsoft Visual Studio IDE or Developer Command Prompt for Visual Studio.

Example: `msbuild.exe /p:Configuration=Release /flp1:LogFile=build.log MasterCard-Core.sln`

Package the DLLs into a NuGet package using the command `nuget pack MasterCard-Core.dll.nuspec`.

## Tests
This project contains NUnit tests which can be run using NUnit Test Runner, `dotnet test` or within the IDE.

The tests require the [Mock Server](https://github.com/Mastercard/mock_crud_server) to be running on http://localhost:8081

_Some tests requires connectivity with Mastercard API's sandbox (https://sandbox.api.mastercard.com). These tests have been marked as `Ignore`. You can enable these tests by providing the correct certicates and authentication credentials._

# Usage / Support
For detailed usage instructions and support, visit [Mastercard Developer site](https://developer.mastercard.com)