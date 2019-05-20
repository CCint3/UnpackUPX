@echo on
adb push inject /data/local/tmp
adb push libdumpUPX.so /data/local/tmp
adb shell su -c chmod 777 /data/local/tmp/libdumpUPX.so
adb shell su -c chmod 777 /data/local/tmp/inject

adb shell su -c chown root:root /data/local/tmp/inject
adb shell su -c chown root:root /data/local/tmp/libdumpUPX.so

adb shell su -c rm -rf /data/local/tmp/unpack
adb shell su -c mkdir /data/local/tmp/unpack
adb shell su -c chmod 777 /data/local/tmp/unpack
adb push %1 /data/local/tmp/unpack
REM adb shell su -c "/data/local/tmp/inject com.illuminate.texaspoker /data/local/tmp/libdumpUPX.so %~nx1"
adb shell su -c "/data/local/tmp/inject com.Autel.maxi /data/local/tmp/libdumpUPX.so %~nx1"
adb shell su -c "chmod 777 /data/local/tmp/unpack/dump.so"
adb pull /data/local/tmp/unpack/dump.so
copy dump.so diag.so
del dump.so

pause

