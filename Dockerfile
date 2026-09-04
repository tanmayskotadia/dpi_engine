# ── Stage 1: Build the C++ DPI Engine ─────────────────────────────────────────
FROM node:20-bookworm AS builder

# Install C++ build tools and CMake
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy C++ source files for engine compilation
COPY CMakeLists.txt ./
COPY include/ ./include/
COPY src/ ./src/

# Build the C++ engine
RUN mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    cmake --build . --config Release && \
    echo "Engine built successfully"

# ── Stage 2: Build the Frontend ───────────────────────────────────────────────
COPY frontend/package.json frontend/package-lock.json* ./frontend/
RUN cd frontend && npm ci

COPY frontend/ ./frontend/
RUN cd frontend && npm run build

# ── Stage 3: Production Image ─────────────────────────────────────────────────
FROM node:20-bookworm-slim AS production

WORKDIR /app

# Copy backend package files and install production dependencies
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Copy the compiled C++ engine from builder
COPY --from=builder /app/build/packet_analyzer ./build/packet_analyzer
RUN chmod +x ./build/packet_analyzer

# Copy the built frontend
COPY --from=builder /app/frontend/dist ./frontend/dist

# Copy server code
COPY server/ ./server/

# Create upload directories
RUN mkdir -p uploads/outputs && \
    mkdir -p server/data

# Render uses PORT env variable (default 10000)
ENV PORT=10000
ENV NODE_ENV=production

EXPOSE ${PORT}

CMD ["node", "server/server.js"]
