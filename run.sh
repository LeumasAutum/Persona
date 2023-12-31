#!/bin/bash
echo -e "\n"
echo    " ███████   ██████    ██████     █████   " 
echo    " ██        ██   ██   ██   ██   ██   ██  "
echo    " ███████   ██████    ██    ██  ███████  " 
echo    "      ██   ██        ██   ██   ██   ██  " 
echo    " ███████   ██        ██████    ██   ██  "   
printf "\n\t\e[1;33m  Version 0.1\n\n  \e[0m\n"  
   
                                        


var="$1"

function validate_ip () {
local IP=$1
local stat=1

if [[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    OIFS=$IFS
    IFS='.'
    ip=($IP)
    IFS=$OIFS
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
        && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    stat=$?
fi
if [ "$stat" -eq 0 ]; then
   return $stat
else
   echo 'Bad IP'
   exit 1   
fi
}

function validate_port () {
local PORT=$1
if [ -z "$PORT" ]; then
    echo 'Port can not be empty'
    exit 1
fi    
if [ "$PORT" -gt 1024 ] && [ "$PORT" -lt 65535 ]; then
    return 0
else
    echo 'Invalid Port'
    exit 1
fi    
}

if [ ! -z "$var" ]; then
    IP=$(echo $var | awk -F':' '{print $1}')
    PORT=$(echo $var | awk -F':' '{print $2}')
    validate_ip $IP
    validate_port $PORT
 else
    IP='0.0.0.0'
    PORT='8000'
fi	
source venv/bin/activate && python3 -m gunicorn -b ${IP}:${PORT} APTRS.wsgi:application --workers=1 --threads=10 --timeout=5600