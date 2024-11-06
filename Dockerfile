# Start from a base Linux image with Rust
FROM rust:1.82

# Install git, cmake, wireshark, and libclang-dev
RUN apt-get update && \
    apt-get install -y \
    git \
    cmake \
    wireshark=4.4.1-1 \
    wireshark-dev=4.4.1-1 \
    tshark=4.4.1-1 \
    libwireshark-dev=4.4.1-1 \
    libclang-dev  # Install libclang for bindgen

# Create a directory to store the Rust project
WORKDIR /usr/src/wsdf

# Clone the specific branch of your GitHub repository
RUN git clone --branch amit/upgrade-ws-1 https://github.com/amitrahman1026/wsdf.git .

# Build the project dependencies (optional step if you want to pre-build)
RUN cargo build --features bindgen

# Set the entrypoint for the container to bash, allowing for interactive access
ENTRYPOINT ["/bin/bash"]

