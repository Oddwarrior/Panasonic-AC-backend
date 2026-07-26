# Panasonic-AC-backend

This is the backend service for the Panasonic AC Smart Dashboard. It acts as an unofficial client for the Panasonic MirAIe API to provide monitoring, control, and analytics for Panasonic Smart ACs.

## Features

- **MirAIe Authentication:** Securely login using your official MirAIe credentials (mobile/email and password).
- **Device Discovery:** Automatically discovers your registered homes and devices via the MirAIe REST API.
- **Real-Time MQTT Integration:** Connects directly to the MirAIe MQTT broker to receive instant telemetry on AC status (temperature, power, fan speed, modes, etc.) and online connection status.
- **AC Control:** Complete control over your AC unit including Power, Temperature, HVAC Mode, Fan Speed, Swing Modes, Display Toggle, Converti Mode, and custom Presets (Eco, Boost, Clean).
- **Energy Analytics:** Fetch daily, weekly, and monthly power consumption data directly from the MirAIe cloud.
- **Telemetry Logging:** Integrates with MongoDB to log AC status changes for historical analytics and background sessions.
- **Dynamic Tariff Calculation:** Uses OpenStreetMap geocoding to resolve your AC's location to calculate localized, regional energy tariffs.

## Prerequisites

- Node.js (v20 or higher)
- MongoDB (optional, for telemetry and background sessions)
- Docker & Docker Compose (optional, for containerized deployment)

## Environment Variables

Create a `.env` file in the root directory (you can use `.env.example` as a template) and configure the following variables:

```env
PORT=5005
MIRAIE_CLIENT_ID="PBcMcfG19njNCL8AOgvRzIC8AjQa" # Required for MirAIe Authentication
MONGODB_URI="mongodb+srv://<username>:<password>@cluster..." # Required for analytics
GEMINI_API_KEY="..." 
```

## Running the Server

### Local Development

1. Install dependencies:
   ```bash
   npm install
   ```
2. Start the server:
   ```bash
   npm start
   ```

### Docker

To run the application in an isolated container:

1. Build and start the container:
   ```bash
   docker-compose up -d --build
   ```
2. View logs:
   ```bash
   docker-compose logs -f
   ```

## Key API Endpoints

- `POST /api/auth/login` - Authenticate with MirAIe
- `POST /api/auth/logout` - Logout and terminate session
- `GET /api/devices` - List discovered AC units
- `GET /api/devices/:deviceId/status` - Get real-time device status
- `POST /api/devices/:deviceId/control` - Send control commands (e.g., power, temperature, mode)
- `GET /api/devices/:deviceId/tariff` - Fetch regional electricity tariff based on AC location
- `GET /api/analytics` - Fetch telemetry analytics from MongoDB
- `GET /api/analytics/energy` - Fetch historical power consumption data
