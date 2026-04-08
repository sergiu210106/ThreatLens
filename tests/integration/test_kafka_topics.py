import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "infra" / "docker-compose.yml"


def run(cmd, capture_output=False, text=True, check=True):
    return subprocess.run(
        cmd,
        capture_output=capture_output,
        text=text,
        check=check,
        cwd=ROOT,
    )


@pytest.fixture(scope="module")
def docker_compose_up():
    if shutil.which("docker") is None:
        pytest.skip("Docker is not available in the environment")

    try:
        run(["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d", "zookeeper", "kafka"])
        run(["docker", "compose", "-f", str(COMPOSE_FILE), "run", "--rm", "kafka-init"])
        yield
    finally:
        run(["docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"], check=False)


def test_kafka_topics_exist(docker_compose_up):
    expected_topics = {"raw-cves", "raw-reports", "raw-pastes"}
    for _attempt in range(30):
        result = run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE_FILE),
                "exec",
                "-T",
                "kafka",
                "bash",
                "-lc",
                "kafka-topics --bootstrap-server localhost:9092 --list",
            ],
            capture_output=True,
        )
        topics = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        if expected_topics.issubset(topics):
            break
        time.sleep(2)
    else:
        pytest.fail(f"Kafka topics not available after timeout: {expected_topics - topics}")

    fres = run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "exec",
            "-T",
            "kafka",
            "bash",
            "-lc",
            "kafka-topics --bootstrap-server localhost:9092 --describe --topic raw-cves",
        ],
        capture_output=True,
    )
    assert "PartitionCount:" in fres.stdout
    assert "ReplicationFactor:" in fres.stdout
    assert "Configs:" in fres.stdout


def test_kafka_can_produce_and_consume_message(docker_compose_up):
    message = "integration-test-message"
    run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "exec",
            "-T",
            "kafka",
            "bash",
            "-lc",
            f"printf '%s' '{message}' | kafka-console-producer --broker-list localhost:9092 --topic raw-cves",
        ],
        check=True,
    )

    result = run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "exec",
            "-T",
            "kafka",
            "bash",
            "-lc",
            "timeout 15 kafka-console-consumer --bootstrap-server localhost:9092 --topic raw-cves --from-beginning --max-messages 1",
        ],
        capture_output=True,
    )
    assert message in result.stdout
