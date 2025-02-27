#!/bin/bash

# Save script to a permanent location
SCRIPT="/home/sysens/traffic-anonymization/scripts/run_traffic_an.sh"
SCRIPT_PATH="/home/sysens/run_traffic_an.sh"
cp "$SCRIPT" "$SCRIPT_PATH"
chmod +x "$SCRIPT_PATH"

# Create a crontab entry that runs every minute
# (This is the minimum granularity for cron)
CRON_ENTRY="* * * * * root $SCRIPT_PATH"

# Add to crontab
echo "$CRON_ENTRY" > /etc/cron.d/traffic_an