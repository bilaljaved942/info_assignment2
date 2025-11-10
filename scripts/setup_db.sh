#!/bin/bash
# Setup MySQL database and user for secure chat app

echo "Creating MySQL database and user..."

# MySQL root commands
mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS securechat;
CREATE USER IF NOT EXISTS 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
EOF

echo "Database setup complete!"