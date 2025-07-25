#!/bin/bash
sleep 60
curl -u admin:admin -X POST "http://localhost:9000/api/users/change_password?login=admin&password=2301831@sit.singaporetech.edu.sg&previousPassword=admin"
echo "Password changed to 2301831@sit.singaporetech.edu.sg"