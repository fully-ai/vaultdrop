FROM python:3.12-slim

WORKDIR /app
RUN useradd --create-home --shell /bin/bash appuser

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

USER appuser
ENV VAULTDROP_HOST=0.0.0.0 \
    VAULTDROP_PORT=8090 \
    VAULTDROP_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8090
CMD ["vaultdrop"]
