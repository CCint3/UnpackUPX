@echo on
adb push inject /data/local/tmp
adb push libdumpUPX.so /data/local/tmp
adb shell chmod 777 /data/local/tmp/inject
adb shell mkdir /data/local/tmp/unpack
adb shell rm -rf /data/local/tmp/unpack/*
adb push %1 /data/local/tmp/unpack
adb shell "/data/local/tmp/inject com.Autel.maxi /data/local/tmp/libdumpUPX.so %~nx1"
adb shell "chmod 777 /data/local/tmp/unpack/dump.so"
adb pull /data/local/tmp/unpack/dump.so
copy dump.so diag.so
del dump.so

pause

