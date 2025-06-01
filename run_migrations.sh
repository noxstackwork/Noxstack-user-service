#!/bin/bash

# Database connection parameters
DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="noxstack_user"
DB_USER="sivakumar"
DB_PASSWORD=""

echo "Running database migrations..."

# Run the migration
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f migrations/001_create_tables.sql

if [ $? -eq 0 ]; then
    echo "✅ Migrations completed successfully!"
else
    echo "❌ Migration failed!"
    exit 1
fi 