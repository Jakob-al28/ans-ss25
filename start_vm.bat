@echo off
set VAGRANT_PREFER_SYSTEM_BIN=0

echo ===============================
echo Starting the virtual machine with 'vagrant up'
echo This will launch the VM if it's not already running.
echo ===============================
vagrant up

echo.
echo ========================================
echo Opening an SSH session and launching a GUI application
echo This will:
echo - Connect to the VM via SSH
echo - Set up DISPLAY forwarding to your host (10.0.2.2:0.0)
echo - Launch 'xterm' from inside the VM
echo Make sure your X server (like VcXsrv or Xming) is running!
echo ========================================
vagrant ssh -c "sudo apt-get install -y xterm && export DISPLAY=$(route -n | grep '^0.0.0.0' | awk '{print $2}'):0 && xterm"
echo 127.0.0.1:6000