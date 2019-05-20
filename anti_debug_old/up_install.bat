@echo on
adb push inject /data/local/tmp
adb push libdumpUPX.so /data/local/tmp
adb shell su -c "chmod 777 /data/local/tmp/inject"
adb shell su -c "mkdir /data/local/tmp/unpack"
adb shell su -c "rm -rf /data/local/tmp/unpack/*"
adb push %1 /data/local/tmp/unpack
rem com.cnlaunch.x431.diag
rem com.Autel.maxi

adb shell su -c "data/local/tmp/inject com.Autel.maxi /data/local/tmp/libdumpUPX.so %~nx1"
adb shell su -c "chmod 777 /data/local/tmp/unpack/dump.so"
adb pull /data/local/tmp/unpack/dump.so

ren %~nx1 %~nx1.old
ren dump.so %~n1.so

pause