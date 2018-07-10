# Introduction
This is the SDK Core API for all the SDK used in Mastercard. 
It provides some Core functionality for all our SDKs.
It provide:
- exception handling
- security (OAUTH)
- crypt utilities
- message pump
- smart map (for inline request creation using fluent style api)

# Setup
This is a C# project.

Build the project using Microsoft Visual Studio with .NET Framework 4.6.1

## Tests
This project has NUnit tests. The dependency is indicated in `packages.config`

The tests require the [Mock Server](https://github.com/Mastercard/mock_crud_server) to be running.

Some tests requires connectivity with Mastercard's API sandbox (https://sandbox.api.mastercard.com). These tests have been marked as `Ignore`.

Execute the tests using NUnit or NUnit Console runner.

# Usage
For detailed usage instructions, visit [Mastercard Developer site](https://developer.mastercard.com)
