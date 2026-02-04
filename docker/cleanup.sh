#!/bin/bash
# Cleanup old snapshot files, bootstrap zips, and rotated logs.
# Keeps only the 2 most recent files of each type to allow safe rollback.
# Runs periodically via supervisord.

DATA_DIR="/data/bob"
INTERVAL=3600  # check every hour

while true; do
    # Keep the 2 most recent spectrum files (by modification time), delete the rest
    SPECTRUM_COUNT=$(ls -t "$DATA_DIR"/spectrum.* 2>/dev/null | wc -l)
    if [ "$SPECTRUM_COUNT" -gt 2 ]; then
        ls -t "$DATA_DIR"/spectrum.* | tail -n +3 | xargs rm -f
        echo "$(date -u '+%Y-%m-%d %H:%M:%S') Cleaned old spectrum files (kept 2 of $SPECTRUM_COUNT)"
    fi

    # Keep the 2 most recent universe files, delete the rest
    UNIVERSE_COUNT=$(ls -t "$DATA_DIR"/universe.* 2>/dev/null | wc -l)
    if [ "$UNIVERSE_COUNT" -gt 2 ]; then
        ls -t "$DATA_DIR"/universe.* | tail -n +3 | xargs rm -f
        echo "$(date -u '+%Y-%m-%d %H:%M:%S') Cleaned old universe files (kept 2 of $UNIVERSE_COUNT)"
    fi

    # Remove all bootstrap zip files (only needed for initial setup)
    ZIP_COUNT=$(ls "$DATA_DIR"/ep*.zip 2>/dev/null | wc -l)
    if [ "$ZIP_COUNT" -gt 0 ]; then
        rm -f "$DATA_DIR"/ep*.zip
        echo "$(date -u '+%Y-%m-%d %H:%M:%S') Removed $ZIP_COUNT bootstrap zip(s)"
    fi

    # Remove rotated log files (bob.1.log, bob.2.log, etc.) - keep only the active bob.log
    ROTATED_LOGS=$(ls "$DATA_DIR"/bob.[0-9]*.log 2>/dev/null | wc -l)
    if [ "$ROTATED_LOGS" -gt 0 ]; then
        rm -f "$DATA_DIR"/bob.[0-9]*.log
        echo "$(date -u '+%Y-%m-%d %H:%M:%S') Removed $ROTATED_LOGS rotated bob log(s)"
    fi

    sleep "$INTERVAL"
done
