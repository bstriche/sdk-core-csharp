#!/bin/bash
echo "Cleaning up"
rm -rf bin/

echo "Building Mastercard-Core-CSharp"
RESPONSE=$(msbuild.exe /p:Configuration=Release /flp1:LogFile=build.log MasterCard-Core.sln | grep -i "Build succeeded\|Build FAILED")

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
RESPONSE=$(nunit3-console.exe bin/Release/MasterCard-Core.dll | tail -n+3 | xmlstarlet sel -t -v "//test-suite[@name='bin/Release/MasterCard-Core.dll']/@success")
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
