# Use official Python image
FROM python:3.11-slim

# Install scapy
RUN pip install scapy

# Set working directory
WORKDIR /app

# Copy your script into the container
COPY pcapnaitor.py .
COPY assignment.pcap .

# Default command: show help if no arguments
CMD ["python", "pcapnaitor.py"]