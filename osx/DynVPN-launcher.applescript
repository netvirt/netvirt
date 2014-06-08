-- Run in background so that following commands can execute while dnc is running. Redirection to /dev/null is necessary for background.
do shell script "/Applications/dnc.app/Contents/MacOS/dnc > /dev/null 2>&1 &" with administrator privileges
