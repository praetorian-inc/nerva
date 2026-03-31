# Gradio ML web UI for fingerprinter testing
FROM python:3.11-slim

# Install Gradio and dependencies
RUN pip install --no-cache-dir "gradio==5.12.0" requests

# Copy test application
COPY app.py /app/app.py
WORKDIR /app

# Expose default Gradio port
EXPOSE 7860

# Health check via /config endpoint
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/config')" || exit 1

# Start Gradio server
CMD ["python", "app.py"]
