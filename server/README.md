# Merklin Server

This is the server for the Merklin tamper-proof logging system.

## Setup

1.  Create a `.env` file from the `.env.example`:
    ```bash
    cp .env.example .env
    ```
2.  Edit the `.env` file with your Firebase credentials path and email settings.

    ```
    MERKLIN_FIREBASE_CREDS=/path/to/your/firebase-credentials.json
    MERKLIN_EMAIL_USER=your-email@gmail.com
    MERKLIN_EMAIL_PASSWORD=your-app-password
    ```

## Installation

```bash
uv pip install 'merklin @ git+https://github.com/TotalyEnglizLitrate/merklin#subdirectory=server'
```

For development, see the root README.

## Usage

```bash
python -m merklin
```
