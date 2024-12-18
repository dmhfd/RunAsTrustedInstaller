windres.exe -o 1.res -O COFF 1.rc
gcc RunAsTrustedInstaller.cpp 1.res -o RunAsTrustedInstaller.exe -lntdll
pause