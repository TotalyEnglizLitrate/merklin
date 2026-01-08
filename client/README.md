# Arthur - The Merklin Client

`arthur` is the client for the Merklin tamper-proof logging system. It sends logs to the Merklin server.

## Setup

1.  Create a `.env` file from the `.env.example`:
    ```bash
    cp .env.example .env
    ```
2.  Edit the `.env` file with your server URL and token.

    ```
    MERKLIN_URL=localhost:8000
    MERKLIN_TOKEN=mysecrettoken
    ```

The token can be obtained by visiting the root server URL in your web browser.

## Installation

```bash
uv add 'arthur @ git+https://github.com/TotalyEnglizLitrate/merklin#subdirectory=client'
```

For development, see the root README.

## Usage
### Log Sending
See example.py for a more comprehensive/filled out example
```python
from arthur import hook_logs

...

log_file = open("my_log_file.log", "w+") # can be any text mode that supports both reading and writing
hooked_file = hook_logs()

...

logger.addHandler(logging.StreamHandler(hooked_file)) # `logger is your existing logger instance from stdlib logging

try:
    # operations - ideally a single entrypoint function defined elsewhere
    ...
finally:
    handler.flush()
    logger.removeHandler(handler)
    handler.close()

    time.sleep(1)
```

### Log Retrieval
```bash
python -m arthur
```
