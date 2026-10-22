#!/bin/bash
cd ~/selfearner-agents/agt_60ca3cc165c9
pgrep -f "python3 server.py" >/dev/null || (setsid nohup python3 server.py >>/tmp/server.log 2>&1 < /dev/null &)
