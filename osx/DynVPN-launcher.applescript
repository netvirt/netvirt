-- Run in background so that following commands can execute while dnc is running. Redirection to /dev/null is necessary for background.
do shell script "/Applications/dnc.app/Contents/MacOS/dnc > /dev/null 2>&1 &" with administrator privileges
-- Wait for dnc to start ...
do shell script "sleep 1"
-- Put dnc on top of the other windows
tell application "System Events"
	set frontmost of process "dnc" to true
end tell
