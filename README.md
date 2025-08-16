# PhantomDNS

PhantomDNS is a DNS-layer security & privacy gateway designed to operate on small hardware (Raspberry Pi, NUC) or as a cloud container.

It intercepts DNS queries, applies security policies, blocks malware, trackers, ads, and provides reporting & CLI administration.

## Setup

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/lopster568/PhantomDNS.git
    cd PhantomDNS
    ```

2.  **Build and run the services using Docker Compose:**
    ```sh
    docker-compose up --build
    ```

## Usage

The control plane and data plane services will be running in the background.

-   **Data Plane (DNS Server):** Listening on port `1053` (UDP and TCP).
-   **Control Plane (Admin API):** Listening on port `8086`.

Further instructions on how to use the CLI and API will be added here.
