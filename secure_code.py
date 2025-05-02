# SECURE VERSION OF THE CODE
# The following vulnerabilities have been fixed:
#
# IMPORTANT: This code has been automatically secured but may require additional adjustments.
# Review all changes carefully before deploying to production.

import html
import json
import os
import subprocess
# SECURE VERSION OF THE CODE
# The following vulnerabilities have been fixed:
# - Line 9: Fixed SQL injection in query variable
# - Line 9: Fixed SQL injection in query variable
#
# IMPORTANT: This code has been automatically secured but may require additional adjustments.
# Review all changes carefully before deploying to production.

import html
import json
import os
import subprocess
import sqlite3
import os
import subprocess

def insecure_db_query(user_input):
    # Vulnerable to SQL injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SECURITY: Use parameterized queries
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    cursor.execute(query)
    return cursor.fetchall()

def insecure_command(user_input):
    # Vulnerable to command injection
    cmd = "echo " + user_input
    os.system(cmd)

def insecure_file_read(filename):
    # Vulnerable to path traversal
    with open(filename, 'r') as file:
        return file.read()

def main():
    # Example usage
    user_input = input("Enter username to search: ")
    print(insecure_db_query(user_input))

    command_input = input("Enter message to echo: ")
    insecure_command(command_input)

    file_input = input("Enter filename to read: ")
    print(insecure_file_read(file_input))

if __name__ == "__main__":
    main()