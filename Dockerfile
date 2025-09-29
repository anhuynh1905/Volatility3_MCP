FROM python:3-slim

WORKDIR /app

COPY requirements.txt .
COPY /project .

RUN pip install -r requirements.txt

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        python3-dev && \
    \
    pip install --no-cache-dir volatility3 && \
    pip install --no-cache-dir -e "volatility3[dev]" && \
    \
    # Clean up the build tools and apt lists
    apt-get remove -y build-essential cmake python3-dev && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


CMD [ "python3", "volatility3/vol.py", "-h" ]