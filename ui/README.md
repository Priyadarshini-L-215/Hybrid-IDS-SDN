# Anti-Gravity IDS Dashboard (React)

A high-performance, real-time security dashboard for the Hybrid IDS system. Built with **React**, **Vite**, and **Lucide React** for enterprise-grade network monitoring.

## 🚀 Key Features

*   **Real-time WebSocket Stream**: Subscribes to `ws://localhost:5000/ws/alerts` for instantaneous threat visualization.
*   **Attack Lab**: Integrated Nmap scanner interface to simulate network events and verify detector responsiveness.
*   **Glassmorphic Design**: A premium, cybersecurity-focused aesthetic designed for low-light SOC environments.
*   **Adaptive Fallback**: Gracefully falls back to polling if the WebSocket relay is interrupted.

## 🛠️ Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The Vite dev server is configured to proxy API requests to the Flask backend on `http://127.0.0.1:5000`.

## 📜 Scripts

- `npm run dev`: Starts the local development environment.
- `npm run build`: Compiles optimized assets for the `/dist` folder.
- `npm run lint`: Performs static analysis for code quality.
