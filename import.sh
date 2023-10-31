#!/bin/bash

# Check if the SQLite3 command-line tool is installed
if ! command -v sqlite3 &> /dev/null; then
    echo "SQLite3 is not installed. Please install it first."
    exit 1
fi

# Check if the user provided a directory containing CSV files
if [ $# -ne 1 ]; then
    echo "Usage: $0 <csv_directory>"
    exit 1
fi

# Assign the provided directory to a variable
csv_directory="$1"

# Check if the directory exists
if [ ! -d "$csv_directory" ]; then
    echo "Directory '$csv_directory' does not exist."
    exit 1
fi

# List CSV files in the directory
csv_files=$(find "$csv_directory" -type f -name "*.csv")

# Check if there are any CSV files
if [ -z "$csv_files" ]; then
    echo "No CSV files found in the directory '$csv_directory'."
    exit 1
fi

# Database file name
database_file="db.sqlite3"

# Loop through each CSV file and import it into the database
for csv_file in $csv_files; do
    # Extract table name from the CSV file name
    table_name=$(basename "$csv_file" .csv)

    # Use .mode csv and .import commands to import CSV into the database
    sqlite3 "$database_file" ".mode csv" ".import $csv_file $table_name"

    # Check if the import was successful
    if [ $? -eq 0 ]; then
        echo "Imported '$csv_file' into table '$table_name'"
    else
        echo "Failed to import '$csv_file' into table '$table_name'"
    fi
done

echo "CSV import completed."
