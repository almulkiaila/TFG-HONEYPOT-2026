#!/bin/bash
echo "=== PRUEBA 1: Canary access (100700) ==="
sshpass -p 'admin' ssh -o StrictHostKeyChecking=no admin@localhost -p 2222 << 'EOF'
ls
cat config.env
exit
EOF
sleep 5

echo "=== PRUEBA 2: Privilege escalation (100502) ==="
sshpass -p 'admin' ssh -o StrictHostKeyChecking=no admin@localhost -p 2222 << 'EOF'
whoami
sudo -l
sudo cat /etc/shadow
exit
EOF
sleep 5

echo "=== PRUEBA 3: Data exfiltration (100503) ==="
sshpass -p 'admin' ssh -o StrictHostKeyChecking=no admin@localhost -p 2222 << 'EOF'
ls
cat db_backup_2025.sql
cat salaries_2025.csv
exit
EOF
sleep 5

echo "=== PRUEBA 4: Cross-vector correlation (100600) ==="
sshpass -p 'admin' ssh -o StrictHostKeyChecking=no admin@localhost -p 2222 << 'EOF'
cat config.env
exit
EOF
sleep 3
curl -s http://localhost:8888/dashboard > /dev/null
curl -s http://localhost:8888/contacts > /dev/null
sleep 5

echo "=== PRUEBA 5: Consistency (x3) ==="
for i in 1 2 3; do
  echo "--- Run $i ---"
  sshpass -p 'admin' ssh -o StrictHostKeyChecking=no admin@localhost -p 2222 << 'EOF'
whoami
ls
cat salaries_2025.csv
sudo -l
exit
EOF
  sleep 8
done

echo "=== RECOPILANDO RESULTADOS ==="
sleep 30
echo "--- alerts.log ---"
sudo grep -o "Rule: [0-9]*" /var/ossec/logs/alerts/alerts.log | sort | uniq -c | sort -rn | head -20
echo "--- ultimas alertas honeypot ---"
sudo grep "100[0-9][0-9][0-9]" /var/ossec/logs/alerts/alerts.log | tail -30
echo "--- llm_events ---"
tail -50 llm_events.json