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

Build the project using Microsoft Visual Studio.

## Tests
This project has NUnit tests. The dependency is indicated in `packages.config`

Some of the tests require the [Mock Server](https://github.com/Mastercard/mock_crud_server) up and running. 

Some tests also requires connectivity with Mastercard's API sandbox (https://sandbox.api.mastercard.com)

# Usage
For detailed usage instructions, visit [Mastercard Developer site](https://developer.mastercard.com)
