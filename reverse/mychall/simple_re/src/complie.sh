#! /bin/bash

echo -e "start comple!"
make
echo -e "comple finished!"

echo -e "start add upx"
file="simple_re"
if [ -f $file ]
then
	rm simple_re	
fi

upx -9 simple_re_ -o simple_re
make clean
echo -e "finished!"
