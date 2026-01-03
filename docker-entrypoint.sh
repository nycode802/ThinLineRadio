#!/bin/sh
# ThinLine Radio Docker Entrypoint
# Converts environment variables to command-line flags

set -e

# Build command line arguments from environment variables
ARGS=""

# Database configuration (required)
if [ -n "$DB_TYPE" ]; then
    ARGS="$ARGS -db_type $DB_TYPE"
fi

if [ -n "$DB_HOST" ]; then
    ARGS="$ARGS -db_host $DB_HOST"
else
    echo "ERROR: DB_HOST environment variable is required"
    exit 1
fi

if [ -n "$DB_PORT" ]; then
    ARGS="$ARGS -db_port $DB_PORT"
fi

if [ -n "$DB_NAME" ]; then
    ARGS="$ARGS -db_name $DB_NAME"
else
    echo "ERROR: DB_NAME environment variable is required"
    exit 1
fi

if [ -n "$DB_USER" ]; then
    ARGS="$ARGS -db_user $DB_USER"
else
    echo "ERROR: DB_USER environment variable is required"
    exit 1
fi

if [ -n "$DB_PASS" ]; then
    ARGS="$ARGS -db_pass $DB_PASS"
else
    echo "ERROR: DB_PASS environment variable is required"
    exit 1
fi

# Server configuration (optional)
if [ -n "$LISTEN" ]; then
    ARGS="$ARGS -listen $LISTEN"
fi

if [ -n "$SSL_LISTEN" ]; then
    ARGS="$ARGS -ssl_listen $SSL_LISTEN"
fi

if [ -n "$SSL_CERT_FILE" ]; then
    ARGS="$ARGS -ssl_cert_file $SSL_CERT_FILE"
fi

if [ -n "$SSL_KEY_FILE" ]; then
    ARGS="$ARGS -ssl_key_file $SSL_KEY_FILE"
fi

if [ -n "$SSL_AUTO_CERT" ]; then
    ARGS="$ARGS -ssl_auto_cert $SSL_AUTO_CERT"
fi

if [ -n "$BASE_DIR" ]; then
    ARGS="$ARGS -base_dir $BASE_DIR"
fi

# Print configuration (without sensitive data)
echo "Starting ThinLine Radio..."
echo "Database: $DB_HOST:${DB_PORT:-5432}/$DB_NAME"
echo "Listen: ${LISTEN:-:3000}"

# Execute the application with built arguments
exec /app/thinline-radio $ARGS "$@"

