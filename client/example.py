import logging
import sys
import time

from arthur import hook_logs


def main():
    capture = open("test_logs.log", "w+")

    hooked_file = hook_logs(capture)

    logger = logging.getLogger("merklin_app")
    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(hooked_file)
    handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    try:
        logger.info("Starting application")
        logger.debug("This is a debug message")
        logger.info("This is a test log entry")
        logger.info("Sending logs to the server...")

        # Simulate some work
        for i in range(5):
            logger.info(f"Processing item {i + 1}")
            time.sleep(0.5)

        logger.info("All done!")

        print("Logs have been sent to Merklin server", file=sys.stderr)

        while True:
            time.sleep(1)  # simulate work

    finally:
        handler.flush()
        logger.removeHandler(handler)
        handler.close()

        time.sleep(1)


if __name__ == "__main__":
    main()
