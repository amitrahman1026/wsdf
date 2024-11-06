# Start from a base Linux image with Rust
FROM rust:1.82

# Add sid (unstable) repositories to apt sources
RUN echo "deb http://deb.debian.org/debian/ sid main" > /etc/apt/sources.list.d/sid.list

# Install build dependencies and wireshark packages
RUN apt-get update && \
    apt-get install -y \
    cmake \
    wireshark=4.4.1-1 \
    wireshark-dev=4.4.1-1 \
    tshark=4.4.1-1 \
    libwireshark-dev=4.4.1-1 \
    libclang-dev



# Create a directory to store the Rust project
WORKDIR /usr/src/wsdf

# Copy the current directory (the Rust project) into the container
COPY . .

# Set the entrypoint for the container to bash, allowing for interactive access
ENTRYPOINT ["/bin/bash"]

