#!/bin/bash

# Configuration
PROGRAM="/home/sysens/traffic-anonymization/traffic-anonymization"
USER="sysens"
INSTANCE1_PARAMS="-conf /home/sysens/traffic-anonymization/config/config_an_ens_if1"
INSTANCE2_PARAMS="-conf /home/sysens/traffic-anonymization/config/config_an_ens_if2"
LOG_FILE="/var/log/traffic_an.log"

# Function to check if an instance is running
check_instance() {
    local params="$1"
    pgrep -f -u "$USER" "$PROGRAM.*$params" > /dev/null
    return $?
}

# Function to start an instance
start_instance() {
    local params="$1"
    echo "$(date): Starting $PROGRAM with params: $params" >> "$LOG_FILE"
    
    # Use nohup to prevent the process from being killed when the script exits
    # Redirect stdout and stderr to a log file and disconnect completely with &
    su - "$USER" -c "nohup $PROGRAM $params > /var/log/ta_${params// /_}.log 2>&1 &"
}

# Check and restart instance 1 if needed
if ! check_instance "$INSTANCE1_PARAMS"; then
    echo "$(date): Instance 1 not running. Restarting..." >> "$LOG_FILE"
    start_instance "$INSTANCE1_PARAMS"
fi

# Check and restart instance 2 if needed
if ! check_instance "$INSTANCE2_PARAMS"; then
    echo "$(date): Instance 2 not running. Restarting..." >> "$LOG_FILE"
    start_instance "$INSTANCE2_PARAMS"
fi

exit 0