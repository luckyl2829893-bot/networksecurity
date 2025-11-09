# Start from a slim Python 3.10 image based on Debian Buster
FROM python:3.10-slim-buster

# Set the working directory inside the container
WORKDIR /app

# Copy all local files into the container's /app directory
COPY . /app

# 1. Set environment variable to prevent interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive

# 2. Install awscli: Run apt update and install in a single layer.
# We also clean the cache to keep the image size small.
RUN apt update -y \
    && apt install awscli -y \
    && apt clean

# 3. Install Python dependencies using pip
# Use 'pip install' on its own line to create an efficient layer
RUN pip install --no-cache-dir -r requirements.txt

# Command to run the application when the container starts
CMD ["python3", "app.py"]