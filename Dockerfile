FROM python:3-slim

WORKDIR /app

COPY requirements.txt .
COPY /project .

RUN pip install -r requirements.txt

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        golang \
        build-essential \
        cmake \
        python3-dev \
        git \
        ca-certificates && \
    \
    pip install --no-cache-dir volatility3 && \
    pip install --no-cache-dir -e "volatility3[dev]" && \
    \
    #Install dwarf2json
    git clone https://github.com/volatilityfoundation/dwarf2json.git && \
    cd dwarf2json/ \
    go build -o /usr/local/bin/dwarf2json && \
    # Clean up the build tools and apt lists
    apt-get remove -y build-essential cmake python3-dev golang && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


#CMD [ "python3", "volatility3/vol.py", "-h" ]