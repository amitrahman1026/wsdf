# Use Debian as base image
FROM debian:bookworm

# Add sid repository for unstable packages
RUN echo "deb http://deb.debian.org/debian/ sid main" > /etc/apt/sources.list.d/sid.list

# Install required packages
RUN apt-get update && \
    apt-get install -y \
    git \
    cmake \
    build-essential \
    clang \
    wireshark=4.4.1-1 \
    wireshark-dev=4.4.1-1 \
    tshark=4.4.1-1 \
    libwireshark-dev=4.4.1-1 \
    libglib2.0-dev \
    libglib2.0-dev-bin \
    && rm -rf /var/lib/apt/lists/*

# Create directory for the plugin
WORKDIR /plugin

# Create the Wireshark plugins directory
RUN mkdir -p /root/.local/lib/wireshark/plugins/4.4/epan

# Copy directory 
COPY . .
# Copy the build script
# COPY build.sh /plugin/
# RUN chmod +x /plugin/build.sh

# Set the entry point to bash
ENTRYPOINT ["/bin/bash"]
