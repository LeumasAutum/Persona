#!/bin/bash

# Check if the SQLite3 command-line tool is installed
if ! command -v sqlite3 &> /dev/null; then
    echo "SQLite3 is not installed. Please install it first."
    exit 1
fi

# Check if the user provided a database file
if [ $# -ne 1 ]; then
    echo "Usage: $0 <database_file>"
    exit 1
fi

# Assign the provided database file to a variable
database_file="$1"

# Check if the database file exists
if [ ! -f "$database_file" ]; then
    echo "Database file '$database_file' does not exist."
    exit 1
fi

# Get a list of table names from the database
table_names=$(sqlite3 "$database_file" ".tables")

# Loop through each table and export its data to a CSV file
for table in $table_names; do
    # Define the CSV file name based on the table name
    csv_file="${table}.csv"

    # Export the table data to the CSV file
    sqlite3 -header -csv "$database_file" "SELECT * FROM $table;" > "$csv_file"

    # Check if the CSV file was created
    if [ -f "$csv_file" ]; then
        echo "Exported '$table' table to '$csv_file'"
    else
        echo "Failed to export '$table' table to '$csv_file'"
    fi
done

echo "CSV export completed."
