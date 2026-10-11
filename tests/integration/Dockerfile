ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv python3-pip ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/fastvps-doctor-venv

COPY . /app
RUN /opt/fastvps-doctor-venv/bin/python -m pip install --no-cache-dir '.[dev]' \
    && useradd --create-home --uid 10001 doctor

ENV PATH="/opt/fastvps-doctor-venv/bin:${PATH}"
ENV FASTVPS_DOCTOR_INTEGRATION=1
USER doctor

CMD ["python", "-m", "pytest", "-m", "integration", "-q"]

