#!/bin/bash
set -euo pipefail

for i in {1..30}; do
  if kafka-topics --bootstrap-server kafka:9092 --list >/dev/null 2>&1; then
    break
  fi
  echo "Waiting for kafka to become available..."
  sleep 2
 done

kafka-topics --bootstrap-server kafka:9092 --create --if-not-exists --topic raw-cves --partitions 3 --replication-factor 1 --config retention.ms=604800000
kafka-topics --bootstrap-server kafka:9092 --create --if-not-exists --topic raw-reports --partitions 3 --replication-factor 1 --config retention.ms=604800000
kafka-topics --bootstrap-server kafka:9092 --create --if-not-exists --topic raw-pastes --partitions 2 --replication-factor 1 --config retention.ms=259200000
