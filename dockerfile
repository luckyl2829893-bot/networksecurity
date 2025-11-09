# Start from a slim Python 3.10 image based on Debian Buster
FROM python:3.10-slim-buster

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first to take advantage of Docker layer caching.
# If requirements.txt doesn't change, this layer and subsequent layers don't rebuild.
COPY requirements.txt /app/

# 1. Install Python dependencies using pip
# Use 'pip install' on its own line to create an efficient layer
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files after dependencies are installed
COPY . /app

# 2. Set environment variable to prevent interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive

# 3. Install awscli and clean up cache in a single, robust layer.
# This pattern ensures the update, install, and cleanup are atomic.
RUN apt-get update -y \
    && apt-get install -y awscli \
    # Remove the list files to minimize the final image size
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Command to run the application when the container starts
CMD ["python3", "app.py"]