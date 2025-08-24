# Anomaly Detector

This project is a Python-based anomaly detector. It analyzes payloads to identify unusual patterns or outliers.

## Installation

### With Docker

To build and run the application using Docker, use the following commands:

```bash
docker build -t anomaly_detector .
docker run anomaly_detector
```

### Local Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/RobertoDeLaCamara/DetectorAnomalias.git
    cd DetectorAnomalias
    ```

2.  Create a virtual environment and activate it:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run the anomaly detector, execute the `main.py` script:

```bash
python main.py
```

## Testing

To run the tests, use `pytest`:

```bash
pytest
```
