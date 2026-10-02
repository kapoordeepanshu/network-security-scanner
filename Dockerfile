FROM python:3.13-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY netscanner ./netscanner
RUN pip install --no-cache-dir . && useradd --create-home scanner
USER scanner
ENTRYPOINT ["netscanner"]
CMD ["--help"]
