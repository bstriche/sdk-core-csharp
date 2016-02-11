#!/bin/bash
echo "Cleaning up"
rm -rf bin/

echo "Building Mastercard-Core-CSharp"
RESPONSE=$(xbuild /p:Configuration=Release /flp1:LogFile=build.log sdk-core-charp.sln | grep -i "Build succeeded\|Build FAILED")

if [[ "$RESPONSE" =~ "FAILED" ]] 
then
	#echo $RESPONSE
	cat build.log
	echo ""
        echo "------------------------"
        echo "------------------------"
        echo "------------------------"
        echo "Error: compiling source code"
        echo "Build FAILED"
        exit
fi

echo "Running Test"
RESPONSE=$(nunit-console bin/Release/Mastercard-Core-CSharp.dll -xmlConsole -nologo | tail -n+3 | xmlstarlet sel -t -v "//test-suite[@name='bin/Release/Mastercard-Core-CSharp.dll']/@success")
if [[ "$RESPONSE" =~ "False" ]]
then
	#echo $RESPONSE
	cat TestResult.xml
	echo ""
	echo "------------------------"
	echo "------------------------"
	echo "------------------------"
        echo "Error: running unit tests"
	echo "Build FAILED"
        exit
fi


echo Build was SUCCESSFULL
