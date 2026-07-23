import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import axios from 'axios';
import { MirAIeClient } from './miraieClient.js';
import { MongoClient, ObjectId } from 'mongodb';
import { encrypt, decrypt } from './cryptoHelper.js';
import crypto from 'crypto';

dotenv.config();

// ─── MongoDB Initialization ────────────────────────────────────────────────
let db = null;
let mongoClient = null;

if (process.env.MONGODB_URI) {
  try {
    mongoClient = new MongoClient(process.env.MONGODB_URI);
    await mongoClient.connect();
    db = mongoClient.db(); // Automatically uses 'panasonic_miraie' database from MONGODB_URI
    console.log('[MongoDB] Successfully connected to database.');

    // Proactively build optimal indexing for telemetry queries
    await db.collection('events').createIndex({ userId: 1, deviceId: 1, timestamp: -1 });
    console.log('[MongoDB] Configured telemetry database indexes.');

    // Proactively build optimal indexing for workflows queries
    await db.collection('workflows').createIndex({ userId: 1, deviceId: 1 });
    console.log('[MongoDB] Configured workflow database indexes.');

    // Backfill updatedAt if not present
    const unsetCount = await db.collection('workflows').countDocuments({ updatedAt: { $exists: false } });
    if (unsetCount > 0) {
      console.log(`[MongoDB] Backfilling updatedAt for ${unsetCount} workflows...`);
      const cursor = db.collection('workflows').find({ updatedAt: { $exists: false } });
      while (await cursor.hasNext()) {
        const doc = await cursor.next();
        const fallbackDate = doc.createdAt || new Date().toISOString();
        await db.collection('workflows').updateOne(
          { _id: doc._id },
          { $set: { updatedAt: fallbackDate } }
        );
      }
      console.log('[MongoDB] Backfilled updatedAt successfully.');
    }
  } catch (error) {
    console.error('[MongoDB] Database connection or indexing failed:', error.message);
  }
} else {
  console.error('[MongoDB] Database connection skipped. MONGODB_URI not found in environment.');
}

const app = express();
const PORT = process.env.PORT || 5005;

// ─── CORS ──────────────────────────────────────────────────────────────────
// Allow requests from any origin (Vercel, localhost, mobile, etc.)
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// ─── Session & Background Connection Stores ──────────────────────────────────
//
// backgroundLoggers Map:
// Key   : MirAIe userId (string)
// Value : { client: MirAIeClient, devices: [], updatedAt: number }
//
// sessions Map (Active API sessions for frontend):
// Key   : MirAIe accessToken (string)
// Value : { userId: string, createdAt: number, lastActivity: number }
//
const backgroundLoggers = new Map();
const sessions = new Map();

// Purge inactive frontend API sessions (no requests for 24 hours) to avoid unbounded token memory growth
setInterval(() => {
  const now = Date.now();
  const maxIdleTime = 24 * 60 * 60 * 1000; // 24 hours
  for (const [token, apiSession] of sessions.entries()) {
    const idleTime = now - (apiSession.lastActivity || apiSession.createdAt);
    if (idleTime > maxIdleTime) {
      sessions.delete(token);
      console.log(`[Server] Inactive API session purged for token …${token.slice(-8)}`);
    }
  }
}, 30 * 60 * 1000); // Check every 30 minutes

function teardownBackgroundLogger(userId) {
  const logger = backgroundLoggers.get(userId);
  if (!logger) return;

  logger.client.logout(); // Ends MQTT, nulls tokens
  backgroundLoggers.delete(userId);
  console.log(`[Server] Background logger torn down for user ${userId}`);
}

// ─── Auth middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Not authenticated. Please login first.' });
  }

  const apiSession = sessions.get(token);
  apiSession.lastActivity = Date.now(); // Update last activity timestamp on any request

  const logger = backgroundLoggers.get(apiSession.userId);
  if (!logger) {
    // If the background logger is not running (e.g. server restarted and user was not restored, or login expired)
    return res.status(401).json({ error: 'Session expired. Please login again.' });
  }

  // Provide req.session to keep compatibility with existing device & control endpoints
  req.session = logger;
  req.session.userId = apiSession.userId;
  req.sessionToken = token;
  next();
}

// ─── Polling helper ─────────────────────────────────────────────────────────
function startPolling(session) {
  if (session.pollingId) clearInterval(session.pollingId);
  session.pollingId = null; // We rely entirely on the real-time MQTT stream. No background REST polling.
}

// ─── Ping Endpoint (For Render Keep-Alive) ──────────────────────────────────
app.get('/api/ping', (req, res) => {
  res.json({ status: 'alive', timestamp: new Date().toISOString() });
});

// ─── POST /api/auth/login ───────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // A. FAST-PATH LOGIN (If user background logger is already running and password matches)
  if (db) {
    try {
      const bgUser = await db.collection('background_users').findOne({ username });
      if (bgUser) {
        const decryptedPassword = decrypt(bgUser.encryptedPassword, bgUser.iv);
        if (decryptedPassword === password) {
          console.log(`[Server] Fast-path login: credentials match for user ${bgUser._id}`);
          const logger = backgroundLoggers.get(bgUser._id);
          if (logger && logger.devices && logger.devices.length > 0) {
            if (logger.client && logger.client.mqttClient && logger.client.mqttClient.connected) {
              const token = crypto.randomBytes(32).toString('hex');
              sessions.set(token, {
                userId: bgUser._id,
                createdAt: Date.now(),
                lastActivity: Date.now()
              });
              console.log(`[Server] Fast-path login successful. Reusing active session for ${bgUser._id}`);
              return res.json({
                message: 'Authentication successful (cached)',
                accessToken: token,
                devices: logger.devices
              });
            } else {
              console.log(`[Server] Background logger found but MQTT not connected. Proceeding with standard login.`);
            }
          }
        }
      }
    } catch (err) {
      console.error('[Server] Fast-path check failed:', err.message);
    }
  }

  try {
    // 1. Authenticate with MirAIe Client
    const client = new MirAIeClient();
    const authData = await client.login(username, password);

    // B. TEARDOWN EXISTING LOGGER BEFORE DISCOVERY (Avoid concurrency conflicts)
    if (backgroundLoggers.has(authData.userId)) {
      console.log(`[Server] Replacing existing background logger for user ${authData.userId} before discovery`);
      teardownBackgroundLogger(authData.userId);
    }

    // 2. Discover devices & fetch initial status
    const devices = await client.discoverDevices();
    for (const dev of devices) {
      await client.fetchDeviceStatus(dev.id);
    }

    // 3. Save/Update credentials in MongoDB background_users collection
    if (db) {
      try {
        const encrypted = encrypt(password);
        await db.collection('background_users').updateOne(
          { _id: authData.userId },
          {
            $set: {
              username,
              encryptedPassword: encrypted.encryptedData,
              iv: encrypted.iv,
              updatedAt: new Date().toISOString()
            }
          },
          { upsert: true }
        );
        console.log(`[MongoDB] Saved/updated background credentials for user ${authData.userId}`);
      } catch (err) {
        console.error('[MongoDB] Failed to save background credentials:', err.message);
      }
    }

    // 4. Initialize or update the background logger
    // If there's an existing background logger for this user, tear it down first to avoid duplicate connections
    if (backgroundLoggers.has(authData.userId)) {
      console.log(`[Server] Replacing existing background logger for user ${authData.userId}`);
      teardownBackgroundLogger(authData.userId);
    }

    // Wire MQTT live updates
    client.onStatusUpdate = async (deviceId, newStatus, rawPayload = {}) => {
      const logger = backgroundLoggers.get(authData.userId);
      if (!logger) return;
      const dev = logger.devices.find(d => d.id === deviceId);
      if (dev) {
        dev.status = newStatus;
        if (db) {
          try {
            let wattage = 0;
            const wattageKeys = ['pwr', 'pw', 'eng', 'power', 'wattage', 'w', 'watts'];
            for (const key of wattageKeys) {
              if (rawPayload[key] !== undefined) {
                wattage = parseFloat(rawPayload[key]);
                break;
              }
            }

            await db.collection('events').insertOne({
              userId: authData.userId,
              deviceId: deviceId,
              timestamp: new Date().toISOString(),
              powerMode: newStatus.powerMode,
              temperature: newStatus.temperature,
              roomTemperature: newStatus.roomTemperature,
              hvacMode: newStatus.hvacMode,
              fanMode: newStatus.fanMode,
              presetMode: newStatus.presetMode,
              wattage: wattage,
              rawPayload: rawPayload
            });
            console.log(`[MongoDB] Logged telemetry event for ${deviceId} (Wattage: ${wattage}W)`);
          } catch (err) {
            console.error('[MongoDB] Failed to log telemetry event:', err.message);
          }
        }
      }
    };

    // Connect MQTT
    client.connectMQTT();

    // Store in backgroundLoggers
    backgroundLoggers.set(authData.userId, {
      client,
      devices,
      updatedAt: Date.now()
    });

    // 5. Create active API session for the frontend
    sessions.set(authData.accessToken, {
      userId: authData.userId,
      createdAt: Date.now(),
      lastActivity: Date.now()
    });

    console.log(`[Server] New active API session created for user ${authData.userId}. Active API sessions: ${sessions.size}, Background loggers: ${backgroundLoggers.size}`);

    return res.json({
      message: 'Authentication successful',
      accessToken: authData.accessToken,
      devices
    });
  } catch (error) {
    console.error('[Server] Login error:', error.message);
    return res.status(401).json({ error: error.message });
  }
});

// ─── POST /api/auth/logout ──────────────────────────────────────────────────
app.post('/api/auth/logout', requireAuth, (req, res) => {
  sessions.delete(req.sessionToken);
  console.log(`[Server] Active API session logged out for token …${req.sessionToken.slice(-8)}`);
  return res.json({ success: true, message: 'Logged out successfully' });
});

// ─── GET /api/devices ───────────────────────────────────────────────────────
app.get('/api/devices', requireAuth, (req, res) => {
  return res.json(req.session.devices);
});

// ─── GET /api/devices/:deviceId/status ─────────────────────────────────────
app.get('/api/devices/:deviceId/status', requireAuth, async (req, res) => {
  const { deviceId } = req.params;
  const { session } = req;
  const device = session.devices.find(d => d.id === deviceId);

  if (!device) {
    return res.status(404).json({ error: 'Device not found' });
  }

  // Return the cached state maintained by the MQTT real-time stream
  return res.json(device.status);
});

// ─── Tariff Geographic Mapping ──────────────────────────────────────────────
const INDIAN_STATES_DB = [
  {
    state: 'Maharashtra',
    rate: 7.50,
    bbox: { minLat: 15.6, maxLat: 22.1, minLon: 72.6, maxLon: 80.9 },
    center: { lat: 19.75, lon: 75.71 }
  },
  {
    state: 'Karnataka',
    rate: 7.00,
    bbox: { minLat: 11.5, maxLat: 18.5, minLon: 74.0, maxLon: 78.6 },
    center: { lat: 15.31, lon: 75.71 }
  },
  {
    state: 'Delhi NCR',
    rate: 4.50,
    bbox: { minLat: 28.2, maxLat: 28.9, minLon: 76.7, maxLon: 77.4 },
    center: { lat: 28.61, lon: 77.20 }
  },
  {
    state: 'West Bengal',
    rate: 7.30,
    bbox: { minLat: 21.5, maxLat: 27.3, minLon: 85.8, maxLon: 89.9 },
    center: { lat: 22.98, lon: 87.85 }
  },
  {
    state: 'Tamil Nadu',
    rate: 6.00,
    bbox: { minLat: 8.0, maxLat: 13.6, minLon: 76.2, maxLon: 80.4 },
    center: { lat: 11.12, lon: 78.65 }
  },
  {
    state: 'Telangana',
    rate: 6.50,
    bbox: { minLat: 15.8, maxLat: 19.9, minLon: 77.2, maxLon: 81.8 },
    center: { lat: 18.11, lon: 79.01 }
  },
  {
    state: 'Gujarat',
    rate: 6.20,
    bbox: { minLat: 20.1, maxLat: 24.7, minLon: 68.1, maxLon: 74.5 },
    center: { lat: 22.25, lon: 71.19 }
  },
  {
    state: 'Uttar Pradesh',
    rate: 6.50,
    bbox: { minLat: 23.8, maxLat: 30.4, minLon: 77.1, maxLon: 84.7 },
    center: { lat: 26.84, lon: 80.74 }
  },
  {
    state: 'Haryana',
    rate: 5.50,
    bbox: { minLat: 27.6, maxLat: 30.6, minLon: 74.4, maxLon: 77.6 },
    center: { lat: 29.05, lon: 76.08 }
  }
];

function mapStateToTariff(stateName) {
  const name = stateName.toLowerCase();
  if (name.includes('maharashtra')) return { state: 'Maharashtra', rate: 7.50 };
  if (name.includes('karnataka')) return { state: 'Karnataka', rate: 7.00 };
  if (name.includes('delhi')) return { state: 'Delhi NCR', rate: 4.50 };
  if (name.includes('west bengal')) return { state: 'West Bengal', rate: 7.30 };
  if (name.includes('tamil nadu')) return { state: 'Tamil Nadu', rate: 6.00 };
  if (name.includes('telangana')) return { state: 'Telangana', rate: 6.50 };
  if (name.includes('gujarat')) return { state: 'Gujarat', rate: 6.20 };
  if (name.includes('uttar pradesh')) return { state: 'Uttar Pradesh', rate: 6.50 };
  if (name.includes('haryana')) return { state: 'Haryana', rate: 5.50 };
  return null;
}

function getFallbackState(lat, lon) {
  // 1. Check bbox matches
  const matches = INDIAN_STATES_DB.filter(s =>
    lat >= s.bbox.minLat && lat <= s.bbox.maxLat &&
    lon >= s.bbox.minLon && lon <= s.bbox.maxLon
  );

  if (matches.length === 1) {
    return matches[0];
  } else if (matches.length > 1) {
    let closest = matches[0];
    let minDist = Infinity;
    for (const match of matches) {
      const dist = Math.pow(match.center.lat - lat, 2) + Math.pow(match.center.lon - lon, 2);
      if (dist < minDist) {
        minDist = dist;
        closest = match;
      }
    }
    return closest;
  }

  // 2. If no bbox matches, pick closest center among all states
  let closest = INDIAN_STATES_DB[0];
  let minDist = Infinity;
  for (const s of INDIAN_STATES_DB) {
    const dist = Math.pow(s.center.lat - lat, 2) + Math.pow(s.center.lon - lon, 2);
    if (dist < minDist) {
      minDist = dist;
      closest = s;
    }
  }

  if (minDist > 100) {
    return null;
  }
  return closest;
}

// ─── GET /api/devices/:deviceId/tariff ─────────────────────────────────────
app.get('/api/devices/:deviceId/tariff', requireAuth, async (req, res) => {
  const { deviceId } = req.params;
  const { session } = req;

  const device = session.devices.find(d => d.id === deviceId);
  if (!device) {
    return res.status(404).json({ error: 'Device not found' });
  }

  const location = device.details?.location;
  if (!location || !Array.isArray(location) || location.length < 2) {
    console.warn(`[Tariff] Location coordinates not found for device ${deviceId}. Using national default.`);
    return res.json({
      rate: 6.50,
      state: 'National Average',
      city: 'India',
      source: 'default'
    });
  }

  const [lon, lat] = location;
  console.log(`[Tariff] Device coordinates: lat=${lat}, lon=${lon}`);

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    const response = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}`, {
      headers: {
        'User-Agent': 'Panasonic-AC-Smart-Dashboard/1.0'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json();
      if (data && data.address) {
        const addr = data.address;
        const country = addr.country || '';
        const stateName = addr.state || '';
        const city = addr.city || addr.town || addr.village || addr.suburb || addr.county || 'Unknown City';

        console.log(`[Tariff] Geocoded location: state=${stateName}, city=${city}, country=${country}`);

        const mapped = mapStateToTariff(stateName);
        if (mapped) {
          return res.json({
            rate: mapped.rate,
            state: mapped.state,
            city: city,
            source: 'geocoded'
          });
        } else if (country.toLowerCase() === 'india' || stateName) {
          return res.json({
            rate: 6.50,
            state: stateName || 'National Average',
            city: city,
            source: 'geocoded_default'
          });
        }
      }
    }
  } catch (error) {
    console.warn(`[Tariff] Geocoding API failed or timed out: ${error.message}. Performing fallback.`);
  }

  const fallback = getFallbackState(lat, lon);
  if (fallback) {
    console.log(`[Tariff] Fallback resolved to state: ${fallback.state} with rate ${fallback.rate}`);
    return res.json({
      rate: fallback.rate,
      state: fallback.state,
      city: 'Region',
      source: 'fallback'
    });
  }

  console.log(`[Tariff] Ultimate fallback to National Average.`);
  return res.json({
    rate: 6.50,
    state: 'National Average',
    city: 'India',
    source: 'fallback_default'
  });
});

// ─── POST /api/devices/:deviceId/control ───────────────────────────────────
app.post('/api/devices/:deviceId/control', requireAuth, (req, res) => {
  const { deviceId } = req.params;
  const { action, value } = req.body;
  const { session } = req;

  const device = session.devices.find(d => d.id === deviceId);
  if (!device) {
    return res.status(404).json({ error: 'Device not found' });
  }

  console.log(`[Server] Control: Device=${device.name}, Action=${action}, Value=${value}`);

  try {
    switch (action) {
      case 'power':
        session.client.setPower(device, value === true || value === 'on');
        device.status.powerMode = (value === true || value === 'on') ? 'on' : 'off';
        break;

      case 'temperature':
        session.client.setTemperature(device, parseFloat(value));
        device.status.temperature = Math.round(parseFloat(value));
        break;

      case 'mode':
        session.client.setHVACMode(device, value);
        device.status.hvacMode = value;
        // Preset modes eco/boost are only valid in Cool (and Heat). Clear them for dry/fan/auto.
        if (value === 'dry' || value === 'fan') {
          device.status.presetMode = 'none';
          // Converti is a Cool-only feature
          device.status.convertiMode = 0;
        } else if (value === 'auto') {
          // Converti is not supported in Auto mode
          device.status.convertiMode = 0;
          device.status.presetMode = 'none';
        } else {
          // cool / heat: just clear any active preset
          device.status.presetMode = 'none';
        }
        break;

      case 'fanMode':
        session.client.setFanMode(device, value);
        device.status.fanMode = value;
        break;

      case 'vSwing':
        session.client.setVSwingMode(device, value);
        device.status.vSwingMode = parseInt(value);
        break;

      case 'hSwing':
        session.client.setHSwingMode(device, value);
        device.status.hSwingMode = parseInt(value);
        break;

      case 'display':
        session.client.setDisplayMode(device, value === true || value === 'on');
        device.status.displayMode = (value === true || value === 'on') ? 'on' : 'off';
        break;

      case 'converti':
        session.client.setConvertiMode(device, value);
        device.status.convertiMode = parseInt(value);
        // Converti resets all presets in the AC protocol (acem:off, acpm:off)
        device.status.presetMode = 'none';
        break;

      case 'preset':
        session.client.setPresetMode(device, value);
        device.status.presetMode = value;
        // Setting any preset resets Converti to 0 in the AC protocol (cnv: 0)
        device.status.convertiMode = 0;
        if (value === 'eco') device.status.temperature = 26;
        break;

      default:
        return res.status(400).json({ error: `Unsupported control action: ${action}` });
    }

    return res.json({
      success: true,
      message: `Command '${action}' sent successfully`,
      status: device.status
    });
  } catch (error) {
    console.error('[Server] Command dispatch failed:', error.message);
    return res.status(500).json({ error: error.message });
  }
});

// ─── GET /api/analytics ─────────────────────────────────────────────────────
app.get('/api/analytics', requireAuth, async (req, res) => {
  if (!db) {
    return res.status(503).json({ error: 'Database is not initialized.' });
  }

  const { deviceId, days, startDate, endDate } = req.query;
  const { session } = req;

  if (!deviceId) return res.status(400).json({ error: 'deviceId is required' });

  // Security check: Verify the device belongs to the logged-in user's account
  const device = session.devices.find(d => d.id === deviceId);
  if (!device) {
    return res.status(404).json({ error: 'Device not found or access denied.' });
  }

  try {
    const filter = { userId: session.userId, deviceId };

    if (startDate || endDate) {
      filter.timestamp = {};
      if (startDate) {
        const sDate = new Date(startDate);
        sDate.setHours(0, 0, 0, 0);
        filter.timestamp.$gte = sDate.toISOString();
      }
      if (endDate) {
        const eDate = new Date(endDate);
        eDate.setHours(23, 59, 59, 999);
        filter.timestamp.$lte = eDate.toISOString();
      }
    } else {
      const queryDays = days ? parseInt(days) : 7;
      const minDate = new Date();
      minDate.setDate(minDate.getDate() - queryDays);
      filter.timestamp = { $gte: minDate.toISOString() };
    }

    const docs = await db.collection('events')
      .find(filter)
      .sort({ timestamp: -1 })
      .toArray();

    // Map _id to id to maintain compatibility with front-end expectations
    const sessions = docs.map(doc => ({ id: doc._id, ...doc }));

    return res.json({ sessions });
  } catch (error) {
    console.error('[Server] Analytics fetch error:', error);
    return res.status(500).json({ error: 'Failed to fetch analytics data' });
  }
});

// ─── GET /api/analytics/energy ──────────────────────────────────────────────
app.get('/api/analytics/energy', requireAuth, async (req, res) => {
  const { deviceId, timeframe = '7d', startDate, endDate } = req.query;
  const { session } = req;

  if (!deviceId) return res.status(400).json({ error: 'deviceId is required' });

  // Security check: Verify the device belongs to the logged-in user's account
  const device = session.devices.find(d => d.id === deviceId);
  if (!device) {
    return res.status(404).json({ error: 'Device not found or access denied.' });
  }

  // Format dates according to timeframe & grain
  let periodType = 'Daily';
  let queries = [];

  const now = new Date();

  // Helper to format Date into DDMMYYYY
  const formatDDMMYYYY = (date) => {
    const d = String(date.getDate()).padStart(2, '0');
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const y = date.getFullYear();
    return `${d}${m}${y}`;
  };

  // Helper to format Date into MMYYYY
  const formatMMYYYY = (date) => {
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const y = date.getFullYear();
    return `${m}${y}`;
  };

  if (timeframe === 'custom' || (startDate && endDate)) {
    const start = new Date(startDate);
    const end = new Date(endDate);

    // Calculate range in days
    const diffTime = Math.abs(end - start);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays <= 31) {
      periodType = 'Daily';
      // Fetch an extra 1 day before to prevent timezone gaps
      const adjustedStart = new Date(start);
      adjustedStart.setDate(start.getDate() - 1);
      queries = [{ from: formatDDMMYYYY(adjustedStart), to: formatDDMMYYYY(end) }];
    } else {
      periodType = 'Monthly';
      // Start 1 month before to cover timezone gaps
      const adjustedStart = new Date(start);
      adjustedStart.setMonth(start.getMonth() - 1);

      let currentStart = new Date(adjustedStart);
      while (currentStart <= end) {
        let currentEnd = new Date(currentStart);
        currentEnd.setMonth(currentStart.getMonth() + 5); // Max 6 months inclusive (e.g. May to Oct)
        if (currentEnd > end) {
          currentEnd = new Date(end);
        }

        queries.push({
          from: formatMMYYYY(currentStart),
          to: formatMMYYYY(currentEnd)
        });

        currentStart = new Date(currentEnd);
        currentStart.setMonth(currentEnd.getMonth() + 1);
      }
    }
  } else if (timeframe === '24h') {
    // 24h: fetch Daily grain for the last 3 days to cover all timezone overlaps
    periodType = 'Daily';
    const twoDaysAgo = new Date();
    twoDaysAgo.setDate(now.getDate() - 2);
    queries = [{ from: formatDDMMYYYY(twoDaysAgo), to: formatDDMMYYYY(now) }];
  } else if (timeframe === '7d') {
    // 7d: fetch Daily grain for the last 9 days to cover timezone boundaries
    periodType = 'Daily';
    const eightDaysAgo = new Date();
    eightDaysAgo.setDate(now.getDate() - 8);
    queries = [{ from: formatDDMMYYYY(eightDaysAgo), to: formatDDMMYYYY(now) }];
  } else if (timeframe === '12m') {
    periodType = 'Monthly';

    // Start 12 months ago
    const twelveMonthsAgo = new Date();
    twelveMonthsAgo.setMonth(now.getMonth() - 12);

    let currentStart = new Date(twelveMonthsAgo);
    while (currentStart <= now) {
      let currentEnd = new Date(currentStart);
      currentEnd.setMonth(currentStart.getMonth() + 5); // Max 6 months inclusive
      if (currentEnd > now) {
        currentEnd = new Date(now);
      }

      queries.push({
        from: formatMMYYYY(currentStart),
        to: formatMMYYYY(currentEnd)
      });

      currentStart = new Date(currentEnd);
      currentStart.setMonth(currentEnd.getMonth() + 1);
    }
  } else {
    return res.status(400).json({ error: `Unsupported timeframe: ${timeframe}` });
  }

  try {
    console.log(`[Server] Querying energy consumption using ${queries.length} chunk(s) for timeframe ${timeframe}`);

    const rawConsumptionPromises = queries.map(q =>
      session.client.getEnergyConsumption(deviceId, periodType, q.from, q.to)
        .catch(err => {
          console.error(`[Server] Energy query segment failed from ${q.from} to ${q.to}:`, err.message);
          return [];
        })
    );

    const rawConsumptionResults = await Promise.all(rawConsumptionPromises);
    const rawConsumption = rawConsumptionResults.flat();

    // Map and sanitize the response data
    // Response format: [{"day": "24052026", "power": 1.25}, ...] or [{"month": "052026", "power": 64.3}, ...]
    const consumption = (rawConsumption || []).map(item => {
      const dateKey = periodType === 'Daily' ? item.day : item.month;
      const power = parseFloat(item.power || 0);
      return {
        dateKey,
        power
      };
    });

    return res.json({ periodType, consumption });
  } catch (error) {
    console.error('[Server] Energy analytics error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch actual energy consumption from Panasonic' });
  }
});

// Helper to query Gemini with backup models in case of rate limits/quotas
const callGeminiWithFallback = async (apiKey, requestPayload) => {
  const models = [
    'gemini-2.5-flash',
    'gemini-3.1-flash-lite',
    'gemini-1.5-flash',
    'gemini-2.0-flash'
  ];

  let lastError = null;
  for (const model of models) {
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    let retries = 2; // 2 attempts per model for transient RPM limits
    let delayMs = 1000;

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        console.log(`[Gemini API] Querying model ${model} (Attempt ${attempt}/${retries})...`);
        const response = await axios.post(geminiUrl, requestPayload);
        const candidateText = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!candidateText) {
          throw new Error('Gemini API returned an empty response.');
        }
        return candidateText; // Success!
      } catch (err) {
        lastError = err;
        const status = err.response?.status;

        // If it is a transient rate limit (429) and we have retries left, wait and retry
        if (status === 429 && attempt < retries) {
          console.warn(`[Gemini API] Rate Limit 429 on ${model}. Retrying in ${delayMs}ms...`);
          await new Promise(resolve => setTimeout(resolve, delayMs));
          delayMs *= 2;
        } else {
          // If it is a hard quota failure (e.g. 20/20 daily limit), invalid api key, or we ran out of retries,
          // fall back to the next model in the list
          console.warn(`[Gemini API] Model ${model} failed with status ${status || err.message}. Falling back to next model...`);
          break;
        }
      }
    }
  }

  throw lastError || new Error('All Gemini models failed to respond.');
};

// ─── Workflows API Endpoints ────────────────────────────────────────────────
app.post('/api/workflows/generate-ai', requireAuth, async (req, res) => {
  const { prompt, timezone } = req.body;
  if (!prompt) {
    return res.status(400).json({ error: 'Prompt is required' });
  }

  const apiKey = (process.env.GEMINI_API_KEY || '').replace(/['"]/g, '');
  if (!apiKey) {
    return res.status(400).json({ error: 'Gemini API Key is not configured. Please add GEMINI_API_KEY to backend/.env' });
  }

  const tz = timezone || 'Asia/Kolkata';
  const now = new Date();
  let localTimeStr = '';
  try {
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      weekday: 'long',
      hour12: false
    });
    localTimeStr = formatter.format(now);
  } catch (err) {
    localTimeStr = now.toString();
  }

  try {
    const systemInstruction = `You are an AI assistant designed to create automation schedules (workflows) for a Panasonic AC.
The user will provide a description of their daily routine or preferences. Your job is to output a single JSON object representing the workflow sequence.

The user's current local time is: ${localTimeStr} (Timezone: ${tz}).
Use this current time as the reference to calculate any relative time expressions like "after 15 mins", "in 2 hours", "tonight", "tomorrow morning", etc.

Guidelines for choosing Energy Saving, Presets, and Convertible Modes:
- The AC supports two mutually exclusive modes for regulating compressor power: Presets ("eco") and Convertible Capacity ("converti"). If one is enabled, the other must be disabled (false in enabledActions).
- Do not always set convertible capacity. Take the right decision dynamically based on the user prompt:
  - If the user requests extreme energy savings, minimal power usage, or mentions specific limit percentages, use a low Convertible Capacity stage (set "converti" to 40, 50, or 70 inside "actions", and set "converti" to true in "enabledActions").
  - If the user requests general energy efficiency, moderate saving, or standard eco mode, use the Eco preset (set "preset" to "eco" inside "actions", and set "preset" to true in "enabledActions").
  - If the user requests fast cooling, maximum performance, or mentions it is very hot, use the Powerful preset (set "preset" to "boost" inside "actions", and set "preset" to true in "enabledActions").
  - For normal cooling requests with no mention of power-saving or high performance, leave both disabled (false in enabledActions).

The output must be a valid JSON object matching this structure exactly (DO NOT include comments or union operators in your JSON output):
{
  "name": "Summer Night Sleep",
  "days": [1, 2, 3, 4, 5],
  "runOnce": false,
  "steps": [
    {
      "time": "22:00",
      "actions": {
        "power": "on",
        "mode": "cool",
        "temperature": 24,
        "fanMode": "auto",
        "vSwing": 0,
        "hSwing": 0,
        "preset": "none",
        "converti": 0
      },
      "enabledActions": {
        "power": true,
        "mode": true,
        "temperature": true,
        "fanMode": true,
        "vSwing": false,
        "hSwing": false,
        "preset": false,
        "converti": false
      }
    }
  ]
}

Enforce these strict device compatibility guardrails in the generated JSON:
1. If power is "off", all other enabledActions fields must be false (i.e. only trigger power: "off").
2. Mode dry and fan do NOT support temperature. If mode is dry or fan, temperature's enabledActions must be false.
3. Convertible capacity (converti) is ONLY supported in cool mode. If mode is not cool, converti's enabledActions must be false.
4. Presets (eco, boost) are only supported in cool/heat modes. If mode is dry, fan, or auto, preset's enabledActions must be false (unless preset is "clean", which is nanoe-G and works in auto/dry/fan).
5. Preset and converti are mutually exclusive. If preset is enabled (true in enabledActions), converti must be disabled (false in enabledActions), and vice-versa.
6. Days must be an array of integers representing the repeating days of the week: 0 for Sunday, 1 for Monday, 2 for Tuesday, 3 for Wednesday, 4 for Thursday, 5 for Friday, 6 for Saturday. Default to all days [0,1,2,3,4,5,6] if not specified.
   - If the request is a "runOnce" workflow (e.g. "turn off after 15 mins"), calculate the specific day it will execute (today or tomorrow) and include only that day in the "days" array. For example, if today is Tuesday (2), then "days" should be [2].
7. Trigger times (steps) must be sorted chronologically by time.
8. Set "runOnce" to true if the prompt represents a one-off execution that should be discarded after running (e.g. "turn off AC in 15 mins", "turn on at 6 PM today", "one-time cool at 22:00"). Set "runOnce" to false if it represents a repeating schedule (e.g., "every day at 10 PM", "on weekdays").`;

    const requestPayload = {
      contents: [
        {
          parts: [
            {
              text: `${systemInstruction}\n\nUser Prompt: "${prompt}"`
            }
          ]
        }
      ],
      generationConfig: {
        responseMimeType: "application/json"
      }
    };

    const candidateText = await callGeminiWithFallback(apiKey, requestPayload);

    const generatedJson = JSON.parse(candidateText.trim());

    // Basic structure validation
    if (!generatedJson.name || !Array.isArray(generatedJson.steps)) {
      throw new Error('Invalid workflow structure returned by AI.');
    }

    return res.json(generatedJson);
  } catch (error) {
    console.error('[Server] AI Routine Generation Error:', error.message, error.response?.data);
    const errMsg = error.response?.data?.error?.message || error.message || 'Failed to generate workflow via AI';
    return res.status(500).json({ error: errMsg });
  }
});

app.get('/api/workflows', requireAuth, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Database is not initialized.' });
  const { deviceId } = req.query;
  try {
    const filter = { userId: req.session.userId };
    if (deviceId) {
      filter.deviceId = deviceId;
    }
    const list = await db.collection('workflows').find(filter).toArray();
    return res.json(list);
  } catch (error) {
    console.error('[Server] Failed to fetch workflows:', error);
    return res.status(500).json({ error: 'Failed to fetch workflows' });
  }
});

app.post('/api/workflows', requireAuth, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Database is not initialized.' });
  const { deviceId, name, isActive, runOnce, days, timezone, steps } = req.body;
  if (!deviceId || !name || !Array.isArray(steps)) {
    return res.status(400).json({ error: 'deviceId, name, and steps are required' });
  }

  try {
    const newWorkflow = {
      userId: req.session.userId,
      deviceId,
      name,
      isActive: isActive !== false,
      runOnce: runOnce === true,
      days: days || [0, 1, 2, 3, 4, 5, 6],
      timezone: timezone || 'Asia/Kolkata',
      steps: steps.map(s => ({
        time: s.time, // "HH:MM"
        isActive: s.isActive !== false,
        actions: {
          power: s.actions?.power, // "on" | "off"
          temperature: s.actions?.temperature ? Math.round(parseFloat(s.actions.temperature)) : undefined,
          mode: s.actions?.mode,
          fanMode: s.actions?.fanMode,
          vSwing: s.actions?.vSwing !== undefined ? parseInt(s.actions.vSwing) : undefined,
          hSwing: s.actions?.hSwing !== undefined ? parseInt(s.actions.hSwing) : undefined,
          preset: s.actions?.preset,
          converti: s.actions?.converti !== undefined ? parseInt(s.actions.converti) : undefined
        }
      })),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const result = await db.collection('workflows').insertOne(newWorkflow);
    return res.status(201).json({ id: result.insertedId, ...newWorkflow });
  } catch (error) {
    console.error('[Server] Failed to create workflow:', error);
    return res.status(500).json({ error: 'Failed to create workflow' });
  }
});

app.put('/api/workflows/:id', requireAuth, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Database is not initialized.' });
  const { id } = req.params;
  const { name, isActive, runOnce, days, timezone, steps } = req.body;

  try {
    const updateDoc = {
      updatedAt: new Date().toISOString()
    };
    if (name !== undefined) updateDoc.name = name;
    if (isActive !== undefined) updateDoc.isActive = isActive;
    if (runOnce !== undefined) updateDoc.runOnce = runOnce === true;
    if (days !== undefined) updateDoc.days = days;
    if (timezone !== undefined) updateDoc.timezone = timezone;
    if (steps !== undefined) {
      updateDoc.steps = steps.map(s => ({
        time: s.time,
        isActive: s.isActive !== false,
        actions: {
          power: s.actions?.power,
          temperature: s.actions?.temperature ? Math.round(parseFloat(s.actions.temperature)) : undefined,
          mode: s.actions?.mode,
          fanMode: s.actions?.fanMode,
          vSwing: s.actions?.vSwing !== undefined ? parseInt(s.actions.vSwing) : undefined,
          hSwing: s.actions?.hSwing !== undefined ? parseInt(s.actions.hSwing) : undefined,
          preset: s.actions?.preset,
          converti: s.actions?.converti !== undefined ? parseInt(s.actions.converti) : undefined
        }
      }));
    }

    const result = await db.collection('workflows').updateOne(
      { _id: new ObjectId(id), userId: req.session.userId },
      { $set: updateDoc }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Workflow not found' });
    }

    return res.json({ message: 'Workflow updated successfully' });
  } catch (error) {
    console.error('[Server] Failed to update workflow:', error);
    return res.status(500).json({ error: 'Failed to update workflow' });
  }
});

app.delete('/api/workflows/:id', requireAuth, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Database is not initialized.' });
  const { id } = req.params;

  try {
    const result = await db.collection('workflows').deleteOne({
      _id: new ObjectId(id),
      userId: req.session.userId
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Workflow not found' });
    }

    return res.json({ message: 'Workflow deleted successfully' });
  } catch (error) {
    console.error('[Server] Failed to delete workflow:', error);
    return res.status(500).json({ error: 'Failed to delete workflow' });
  }
});

app.post('/api/workflows/:id/trigger', requireAuth, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Database is not initialized.' });
  const { id } = req.params;
  const { stepIndex } = req.body;

  try {
    const workflow = await db.collection('workflows').findOne({
      _id: new ObjectId(id),
      userId: req.session.userId
    });

    if (!workflow) {
      return res.status(404).json({ error: 'Workflow not found' });
    }

    if (stepIndex === undefined) {
      return res.status(400).json({ error: 'Please specify a stepIndex to trigger' });
    }

    const step = workflow.steps[stepIndex];
    if (!step) {
      return res.status(400).json({ error: 'Step index out of bounds' });
    }

    await executeWorkflowStep(workflow.userId, workflow.deviceId, step.actions);
    return res.json({ message: `Triggered step ${stepIndex} successfully`, actions: step.actions });
  } catch (error) {
    console.error('[Server] Failed to trigger workflow step:', error);
    return res.status(500).json({ error: 'Failed to trigger workflow step' });
  }
});

app.post('/api/chatbot/message', requireAuth, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Database is not initialized.' });
  const { message, timezone, deviceId } = req.body;
  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const apiKey = (process.env.GEMINI_API_KEY || '').replace(/['"]/g, '');
  if (!apiKey) {
    return res.status(400).json({ error: 'Gemini API Key is not configured. Please add GEMINI_API_KEY to backend/.env' });
  }

  const tz = timezone || 'Asia/Kolkata';
  const now = new Date();
  let localTimeStr = '';
  try {
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      weekday: 'long',
      hour12: false
    });
    localTimeStr = formatter.format(now);
  } catch (err) {
    localTimeStr = now.toString();
  }

  try {
    const systemInstruction = `You are a helpful smart AC assistant. The user will provide a command or question in natural language.
Your goal is to classify this message and return a JSON object.

The user's current local time is: ${localTimeStr} (Timezone: ${tz}).
Use this current time as the reference to calculate any relative time expressions like "after 15 mins", "in 2 hours", "tonight", "tomorrow morning", "right now", etc.

Instructions:
1. Classify the message into one of three types:
   - "control": If the user wants to adjust the AC settings immediately (e.g. "turn off the AC", "set temperature to 23 degrees", "mode cool", "silent please", "turn on boost").
   - "workflow": If the user wants to schedule an operation in the future (e.g. "turn off after 15 mins", "turn on at 9 PM on weekends", "schedule eco cooling tomorrow at 7 AM").
   - "conversation": If the user is just saying hi, asking a general question, or seeking information (e.g. "how does the filter clean work", "hello", "what are you").

2. For "control" type:
   - Provide an "actions" object with the key-value pairs representing the changes. Only include the fields the user wants to modify:
     - "power": "on" | "off"
     - "temperature": number (16 to 30)
     - "mode": "cool" | "dry" | "auto" | "fan" | "heat"
     - "fanMode": "auto" | "quiet" | "low" | "medium" | "high"
     - "vSwing": number (0 to 5)
     - "hSwing": number (0 to 5)
     - "preset": "eco" | "boost" | "clean" | "none"
     - "converti": number (0, 40, 50, 70, 80, 90, 100, 110)
     Note: preset and converti are mutually exclusive.
   - Provide a natural, friendly "reply" confirming the changes made.

3. For "workflow" type:
   - Provide a "workflow" object to be saved in MongoDB, which MUST include:
     - "name": A short descriptive name (e.g., "AI One-time Shutdown")
     - "runOnce": true | false (set to true if it's a one-off scheduler, e.g. "after 15 mins", or "tomorrow once")
     - "days": array of day indices (0=Sun, 1=Mon, ..., 6=Sat). For runOnce relative workflows, calculate the day of execution (today or tomorrow) and make it the only item in the array.
     - "steps": array of step items:
       - "time": "HH:MM"
       - "isActive": true
       - "actions": the target actions object (similar fields to control).
       - "enabledActions": object mapping the fields in actions to true/false.
   - Provide a friendly "reply" confirming the schedule.

4. For "conversation" type:
   - Provide only a "reply" string.

Enforce these strict compatibility guardrails for "actions":
- Mode dry and fan do NOT support temperature.
- Convertible capacity (converti) is ONLY supported in cool mode.
- Presets are only supported in cool/heat (except "clean" which works in auto/dry/fan/heat too).
- Preset and converti are mutually exclusive. If preset is enabled, converti must be 0/disabled.

Format your response as a single, valid JSON object matching this structure exactly (DO NOT include markdown block markers or comments):
{
  "type": "control" | "workflow" | "conversation",
  "actions": { ... }, // Only for type "control"
  "workflow": { ... }, // Only for type "workflow"
  "reply": "Natural language response here"
}`;

    const requestPayload = {
      contents: [{
        parts: [{
          text: `${systemInstruction}\n\nUser Input: "${message}"`
        }]
      }],
      generationConfig: {
        responseMimeType: "application/json"
      }
    };

    const candidateText = await callGeminiWithFallback(apiKey, requestPayload);
    const resJson = JSON.parse(candidateText.trim());

    // If type is "control" and deviceId is provided, we can execute the step immediately via MQTT
    if (resJson.type === 'control' && resJson.actions && deviceId) {
      console.log(`[Chatbot] Dispatching direct control action:`, JSON.stringify(resJson.actions));
      try {
        await executeWorkflowStep(req.session.userId, deviceId, resJson.actions);
      } catch (err) {
        console.error('[Chatbot] Failed to execute direct actions:', err.message);
      }
    }

    // If type is "workflow" and deviceId is provided, we save the workflow to MongoDB
    if (resJson.type === 'workflow' && resJson.workflow && deviceId) {
      console.log(`[Chatbot] Creating scheduled workflow:`, JSON.stringify(resJson.workflow));
      try {
        const newWorkflow = {
          userId: req.session.userId,
          deviceId,
          name: resJson.workflow.name || 'AI Chat Routine',
          isActive: true,
          runOnce: resJson.workflow.runOnce === true,
          days: resJson.workflow.days || [0, 1, 2, 3, 4, 5, 6],
          timezone: tz,
          steps: (resJson.workflow.steps || []).map(s => ({
            time: s.time,
            isActive: s.isActive !== false,
            actions: {
              power: s.actions?.power,
              temperature: s.actions?.temperature ? Math.round(parseFloat(s.actions.temperature)) : undefined,
              mode: s.actions?.mode,
              fanMode: s.actions?.fanMode,
              vSwing: s.actions?.vSwing !== undefined ? parseInt(s.actions.vSwing) : undefined,
              hSwing: s.actions?.hSwing !== undefined ? parseInt(s.actions.hSwing) : undefined,
              preset: s.actions?.preset,
              converti: s.actions?.converti !== undefined ? parseInt(s.actions.converti) : undefined
            }
          })),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        const insertResult = await db.collection('workflows').insertOne(newWorkflow);
        resJson.workflow.id = insertResult.insertedId;
      } catch (err) {
        console.error('[Chatbot] Failed to save scheduled workflow:', err.message);
      }
    }

    return res.json(resJson);
  } catch (error) {
    console.error('[Server] Chatbot execution error:', error.message);
    return res.status(500).json({ error: 'Chatbot processing failed' });
  }
});

// Helper to execute workflow step actions via MQTT
async function executeWorkflowStep(userId, deviceId, actions) {
  const logger = backgroundLoggers.get(userId);
  if (!logger) {
    console.warn(`[Scheduler] Cannot execute step: No active background logger for user ${userId}`);
    return;
  }
  const device = logger.devices.find(d => d.id === deviceId);
  if (!device) {
    console.warn(`[Scheduler] Cannot execute step: Device ${deviceId} not found for user ${userId}`);
    return;
  }

  console.log(`[Scheduler] Executing scheduled actions for ${device.name} (${deviceId}):`, JSON.stringify(actions));

  try {
    // 1. Power mode
    if (actions.power !== undefined && actions.power !== null) {
      const isOn = actions.power === 'on' || actions.power === true;
      logger.client.setPower(device, isOn);
      device.status.powerMode = isOn ? 'on' : 'off';
    }

    // 2. HVAC mode
    if (actions.mode !== undefined && actions.mode !== null) {
      logger.client.setHVACMode(device, actions.mode);
      device.status.hvacMode = actions.mode;
      // Preset modes eco/boost are only valid in Cool/Heat. Clear for dry/fan/auto.
      if (actions.mode === 'dry' || actions.mode === 'fan') {
        device.status.presetMode = 'none';
        device.status.convertiMode = 0; // Converti is Cool-only
      } else if (actions.mode === 'auto') {
        device.status.convertiMode = 0;
        device.status.presetMode = 'none';
      } else {
        device.status.presetMode = 'none'; // cool / heat
      }
    }

    // 3. Temperature
    if (actions.temperature !== undefined && actions.temperature !== null) {
      const targetTemp = Math.round(parseFloat(actions.temperature));
      logger.client.setTemperature(device, targetTemp);
      device.status.temperature = targetTemp;
    }

    // 4. Fan mode
    if (actions.fanMode !== undefined && actions.fanMode !== null) {
      logger.client.setFanMode(device, actions.fanMode);
      device.status.fanMode = actions.fanMode;
    }

    // 5. Vertical Swing
    if (actions.vSwing !== undefined && actions.vSwing !== null) {
      logger.client.setVSwingMode(device, actions.vSwing);
      device.status.vSwingMode = parseInt(actions.vSwing);
    }

    // 6. Horizontal Swing
    if (actions.hSwing !== undefined && actions.hSwing !== null) {
      logger.client.setHSwingMode(device, actions.hSwing);
      device.status.hSwingMode = parseInt(actions.hSwing);
    }

    // 7. Preset mode
    if (actions.preset !== undefined && actions.preset !== null) {
      logger.client.setPresetMode(device, actions.preset);
      device.status.presetMode = actions.preset;
      // Setting any preset resets Converti to 0 in the AC protocol (cnv: 0)
      device.status.convertiMode = 0;
      // Eco preset forces the AC to 26°C internally — keep status in sync
      // Only override if the step does not also set a temperature explicitly
      if (actions.preset === 'eco' && (actions.temperature === undefined || actions.temperature === null)) {
        device.status.temperature = 26;
      }
    }

    // 8. Converti mode
    if (actions.converti !== undefined && actions.converti !== null) {
      logger.client.setConvertiMode(device, parseInt(actions.converti));
      device.status.convertiMode = parseInt(actions.converti);
      // Converti resets all presets in the AC protocol (acem:off, acpm:off)
      device.status.presetMode = 'none';
    }

    // Log this scheduled execution event in DB telemetry
    if (db) {
      try {
        await db.collection('events').insertOne({
          userId: userId,
          deviceId: deviceId,
          timestamp: new Date().toISOString(),
          powerMode: device.status.powerMode,
          temperature: device.status.temperature,
          roomTemperature: device.status.roomTemperature,
          hvacMode: device.status.hvacMode,
          fanMode: device.status.fanMode,
          presetMode: device.status.presetMode,
          wattage: 0,
          rawPayload: { scheduledTrigger: true, actions }
        });
        console.log(`[MongoDB Scheduler] Logged automation telemetry event for device ${deviceId}`);
      } catch (dbErr) {
        console.error('[MongoDB Scheduler] Failed to write event log:', dbErr.message);
      }
    }
  } catch (error) {
    console.error(`[Scheduler] Failed to dispatch workflow actions:`, error.message);
  }
}

// Background Scheduler Loop (runs once every 60 seconds)
setInterval(async () => {
  if (!db) return;

  try {
    const now = new Date();
    // Fetch all active workflows
    const workflows = await db.collection('workflows').find({ isActive: true }).toArray();
    if (workflows.length === 0) return;

    for (const workflow of workflows) {
      const tz = workflow.timezone || 'Asia/Kolkata';

      // 1. Get current hour and minute in workflow's timezone
      const timePartsFormatter = new Intl.DateTimeFormat('en-US', {
        timeZone: tz,
        hour12: false,
        hour: '2-digit',
        minute: '2-digit'
      });

      let formattedTime = '';
      try {
        const parts = timePartsFormatter.formatToParts(now);
        const hour = parts.find(p => p.type === 'hour')?.value;
        const minute = parts.find(p => p.type === 'minute')?.value;
        if (hour && minute) {
          formattedTime = `${hour}:${minute}`;
        }
      } catch (err) {
        console.error(`[Scheduler] Timezone conversion failed for ${tz}:`, err.message);
        continue;
      }

      if (!formattedTime) continue;

      // 2. Get current day of week in workflow's timezone (0 = Sunday, 1 = Monday, etc.)
      const dayFormatter = new Intl.DateTimeFormat('en-US', {
        timeZone: tz,
        weekday: 'long'
      });
      let weekdayNum = -1;
      try {
        const weekdayStr = dayFormatter.format(now);
        const weekdayMap = {
          'Sunday': 0, 'Monday': 1, 'Tuesday': 2, 'Wednesday': 3,
          'Thursday': 4, 'Friday': 5, 'Saturday': 6
        };
        weekdayNum = weekdayMap[weekdayStr];
      } catch (err) {
        console.error(`[Scheduler] Day formatting failed for ${tz}:`, err.message);
        continue;
      }

      if (weekdayNum === -1) continue;

      // Check if workflow is active for today
      if (workflow.days && !workflow.days.includes(weekdayNum)) {
        continue;
      }

      // Check if any step time matches the current time and is not disabled
      const matchingStep = workflow.steps.find(step => step.time === formattedTime && step.isActive !== false);
      if (matchingStep) {
        console.log(`[Scheduler] Workflow '${workflow.name}' matches time '${formattedTime}' on day ${weekdayNum}`);
        await executeWorkflowStep(workflow.userId, workflow.deviceId, matchingStep.actions);
        if (workflow.runOnce) {
          console.log(`[Scheduler] Discarding run-once workflow '${workflow.name}' (${workflow._id})`);
          await db.collection('workflows').deleteOne({ _id: workflow._id });
        }
      }
    }
  } catch (err) {
    console.error('[Scheduler] Tick execution failed:', err.message);
  }
}, 60 * 1000);

// ─── Background Loggers Initialization ──────────────────────────────────────
async function startBackgroundLogger(userId, username, password) {
  console.log(`[Background] Starting connection for ${username} (${userId})...`);
  const client = new MirAIeClient();
  const authData = await client.login(username, password);
  const devices = await client.discoverDevices();
  for (const dev of devices) {
    await client.fetchDeviceStatus(dev.id);
  }

  // Wire MQTT live updates
  client.onStatusUpdate = async (deviceId, newStatus, rawPayload = {}) => {
    const logger = backgroundLoggers.get(userId);
    if (!logger) return;
    const dev = logger.devices.find(d => d.id === deviceId);
    if (dev) {
      dev.status = newStatus;
      if (db) {
        try {
          let wattage = 0;
          const wattageKeys = ['pwr', 'pw', 'eng', 'power', 'wattage', 'w', 'watts'];
          for (const key of wattageKeys) {
            if (rawPayload[key] !== undefined) {
              wattage = parseFloat(rawPayload[key]);
              break;
            }
          }

          await db.collection('events').insertOne({
            userId: userId,
            deviceId: deviceId,
            timestamp: new Date().toISOString(),
            powerMode: newStatus.powerMode,
            temperature: newStatus.temperature,
            roomTemperature: newStatus.roomTemperature,
            hvacMode: newStatus.hvacMode,
            fanMode: newStatus.fanMode,
            presetMode: newStatus.presetMode,
            wattage: wattage,
            rawPayload: rawPayload
          });
          console.log(`[MongoDB Background] Logged telemetry event for ${deviceId} (Wattage: ${wattage}W)`);
        } catch (err) {
          console.error('[MongoDB Background] Failed to log telemetry event:', err.message);
        }
      }
    }
  };

  client.connectMQTT();

  backgroundLoggers.set(userId, {
    client,
    devices,
    updatedAt: Date.now()
  });
  console.log(`[Background] Session started successfully for user ${userId}`);
}

async function loginOwnerFromEnv() {
  const username = (process.env.MIRAIE_MOBILE || '').replace(/['"]/g, '');
  const password = (process.env.MIRAIE_PASSWORD || '').replace(/['"]/g, '');

  if (!username || !password || username === '+91xxxxxxxxxx' || password === 'your_miraie_password') {
    console.log('[Auto-Login] Credentials not configured in .env. Skipping owner background session.');
    return;
  }

  console.log(`[Auto-Login] Attempting background login for owner ${username} from .env...`);
  try {
    const client = new MirAIeClient();
    const authData = await client.login(username, password);

    // Save to MongoDB so they are registered in DB for future boots too!
    if (db) {
      try {
        const encrypted = encrypt(password);
        await db.collection('background_users').updateOne(
          { _id: authData.userId },
          {
            $set: {
              username,
              encryptedPassword: encrypted.encryptedData,
              iv: encrypted.iv,
              updatedAt: new Date().toISOString()
            }
          },
          { upsert: true }
        );
        console.log(`[Auto-Login] Saved owner credentials to MongoDB.`);
      } catch (err) {
        console.error('[Auto-Login] Failed to save owner credentials to MongoDB:', err.message);
      }
    }

    // Now start it as a regular background logger
    await startBackgroundLogger(authData.userId, username, password);
  } catch (err) {
    console.error('[Auto-Login] Owner background login failed:', err.message);
  }
}

async function initializeBackgroundLoggers() {
  if (!db) {
    console.warn('[Startup] Database not initialized. Cannot load background loggers.');
    await loginOwnerFromEnv();
    return;
  }

  console.log('[Startup] Loading registered background users from MongoDB...');
  try {
    const users = await db.collection('background_users').find({}).toArray();
    if (users.length === 0) {
      console.log('[Startup] No background users registered in MongoDB.');
      await loginOwnerFromEnv();
      return;
    }

    console.log(`[Startup] Found ${users.length} background user(s) to initialize.`);
    for (const doc of users) {
      const data = doc;
      const userId = doc._id;
      try {
        const password = decrypt(data.encryptedPassword, data.iv);
        await startBackgroundLogger(userId, data.username, password);
        // Stagger initialization by 3 seconds to prevent concurrent login request collisions
        await new Promise(resolve => setTimeout(resolve, 3000));
      } catch (err) {
        console.error(`[Startup] Failed to initialize background logger for user ${userId}:`, err.message);
      }
    }
    console.log('[Startup] Background loggers initialization complete.');
  } catch (error) {
    console.error('[Startup] Failed to load background users from MongoDB:', error.message);
  }
}

async function refreshBackgroundLogger(userId, username, password) {
  const logger = backgroundLoggers.get(userId);
  if (!logger) return;

  console.log(`[Background] Refreshing credentials & connection for ${username} (${userId})...`);
  try {
    const authData = await logger.client.login(username, password);
    logger.client.connectMQTT();
    logger.updatedAt = Date.now();
    console.log(`[Background] Refreshed successfully for user ${userId}`);
  } catch (err) {
    console.error(`[Background] Refresh failed for user ${userId}:`, err.message);
  }
}

// Periodic refresh loop to keep all MQTT connections authenticated and active (every 12 hours)
setInterval(async () => {
  console.log('[Background] Running periodic connection refresh for all background users...');
  if (!db) return;
  try {
    const users = await db.collection('background_users').find({}).toArray();
    users.forEach(async doc => {
      const data = doc;
      const userId = doc._id;
      if (backgroundLoggers.has(userId)) {
        try {
          const password = decrypt(data.encryptedPassword, data.iv);
          await refreshBackgroundLogger(userId, data.username, password);
        } catch (err) {
          console.error(`[Background] Failed to refresh user ${userId}:`, err.message);
        }
      }
    });
  } catch (err) {
    console.error('[Background] Failed to load users for periodic refresh:', err.message);
  }
}, 12 * 60 * 60 * 1000); // 12 hours

// ─── Start server ───────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[Server] Panasonic MirAIe AC server running on port ${PORT}`);
  console.log('[Server] Session isolation: ON (token-based, per-user)');

  // Run the background database-backed connection bootstrapper
  initializeBackgroundLoggers();

  // Render.com Free Tier Keep-Alive: Ping itself every 12 minutes to prevent spin-down
  /*
  const selfUrl = process.env.RENDER_EXTERNAL_URL;
  if (selfUrl) {
    console.log(`[Keep-Alive] Render deployment detected. Setting up self-ping loop on ${selfUrl}`);
    setInterval(async () => {
      try {
        const pingUrl = `${selfUrl.replace(/\/$/, '')}/api/ping`;
        console.log(`[Keep-Alive] Self-pinging to prevent spin-down: ${pingUrl}`);
        const response = await fetch(pingUrl);
        const data = await response.json();
        console.log(`[Keep-Alive] Status: ${response.status} - ${JSON.stringify(data)}`);
      } catch (err) {
        console.error('[Keep-Alive] Self-ping failed:', err.message);
      }
    }, 12 * 60 * 1000); // 12 minutes
  }
  */
});
