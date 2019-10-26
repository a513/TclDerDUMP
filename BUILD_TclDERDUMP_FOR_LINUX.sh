echo "./BUILD_TclDerDump_FOR_LINUX.sh 32|64"
bb=$1
if [ ${bb:=0 } -eq 0   ]
    then 
	echo "Bad type 32|64"
	exit 1
fi
if [ $1 -ne 64  -a $1 -ne 32 ]
    then 
	echo "Bad type 32|64"
	exit 1
fi

a=LINUX32_WRAP664

if [ "$1" -eq "64 " ]
    then 
	a=LINUX64_WRAP664
fi
echo $a
../freewrapTCLSH derdump.tcl -w ../$a/freewrapTCLSH -o tclderdump_linux$1
chmod 755 tclderdump_linux$1

