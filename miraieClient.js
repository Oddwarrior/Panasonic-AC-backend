import axios from 'axios';
import mqtt from 'mqtt';

const AUTH_BASE_URL = 'https://auth.miraie.in/simplifi/v1';
const APP_BASE_URL = 'https://app.miraie.in/simplifi/v1';

export class MirAIeClient {
  constructor() {
    this.accessToken = null;
    this.refreshToken = null;
    this.userId = null;
    this.homeId = null;
    this.devices = [];
    this.mqttClient = null;
    this.onStatusUpdate = null; // Callback for live MQTT status updates
    this.clientId = (process.env.MIRAIE_CLIENT_ID || 'your_miraie_client_id').replace(/['"]/g, '');
    // commandLockUntil: Map<deviceId, timestamp>
    // Suppresses incoming MQTT status echoes for 3s after a command is sent
    // to prevent the AC's echo-back from overwriting the freshly-applied state.
    this.commandLockUntil = new Map();
  }

  // Get auth headers
  getHeaders() {
    return {
      'Authorization': `Bearer ${this.accessToken}`,
      'Content-Type': 'application/json'
    };
  }

  // Login
  async login(username, password) {
    const isEmail = username.includes('@');
    const data = {
      clientId: this.clientId,
      password: password,
      scope: 'an_' + Math.floor(Math.random() * 9999999999)
    };

    if (isEmail) {
      data.email = username;
    } else {
      // Ensure mobile has +91 or required country code
      data.mobile = username.startsWith('+') ? username : `+91${username}`;
    }

    console.log(`[MirAIe REST] Attempting login for ${username} (isEmail: ${isEmail})...`);
    
    let response = null;
    const retries = 3;
    let delay = 1000;
    
    for (let i = 0; i < retries; i++) {
      try {
        response = await axios.post(`${AUTH_BASE_URL}/userManagement/login`, data, { timeout: 25000 });
        break; // Success!
      } catch (error) {
        const isTimeout = error.code === 'ECONNABORTED' || error.message.includes('timeout') || error.response?.status === 504;
        const isRateLimit = error.response?.status === 429;
        
        if ((isTimeout || isRateLimit) && i < retries - 1) {
          console.warn(`[MirAIe REST] Login failed (${isTimeout ? 'timeout' : 'rate limit'}). Retrying in ${delay}ms (Attempt ${i + 1}/${retries})...`);
          await new Promise(resolve => setTimeout(resolve, delay));
          delay *= 2; // exponential backoff
        } else {
          console.error('[MirAIe REST] Login request failed:', error.response?.data || error.message);
          throw new Error(error.response?.data?.message || 'Authentication failed');
        }
      }
    }

    const resData = response.data;
    this.accessToken = resData.accessToken;
    this.refreshToken = resData.refreshToken;
    this.userId = resData.userId;

    console.log(`[MirAIe REST] Login successful. User ID: ${this.userId}`);
    return {
      accessToken: this.accessToken,
      refreshToken: this.refreshToken,
      userId: this.userId
    };
  }

  // Logout and clean up MQTT/session states
  logout() {
    console.log('[MirAIe Client] Logging out and cleaning up sessions...');
    if (this.mqttClient) {
      try {
        this.mqttClient.end(true); // Force close immediately
        console.log('[MirAIe Client] MQTT connection terminated.');
      } catch (err) {
        console.error('[MirAIe Client] Error ending MQTT connection:', err.message);
      }
      this.mqttClient = null;
    }

    this.accessToken = null;
    this.refreshToken = null;
    this.userId = null;
    this.homeId = null;
    this.devices = [];
  }

  // Discover devices and fetch home details
  async discoverDevices() {
    if (!this.accessToken) throw new Error('Client not authenticated. Call login first.');

    console.log('[MirAIe REST] Fetching home details...');
    try {
      // 1. Get Homes (with retry for transient auth/delay issues)
      let homesResponse = null;
      let retries = 3;
      let delay = 1000;
      for (let i = 0; i < retries; i++) {
        try {
          homesResponse = await axios.get(`${APP_BASE_URL}/homeManagement/homes`, {
            headers: this.getHeaders(),
            timeout: 10000
          });
          break; // Success!
        } catch (error) {
          const isAuthError = error.response?.status === 401 || error.response?.data?.message === 'Authorization failed';
          const isTimeout = error.code === 'ECONNABORTED' || error.message.includes('timeout');
          if ((isAuthError || isTimeout) && i < retries - 1) {
            console.warn(`[MirAIe REST] Home fetch failed (${isTimeout ? 'timeout' : 'unauthorized'}). Retrying in ${delay}ms...`);
            await new Promise(resolve => setTimeout(resolve, delay));
            delay += 500;
          } else {
            throw error;
          }
        }
      }

      if (!homesResponse.data || homesResponse.data.length === 0) {
        throw new Error('No homes associated with this account');
      }

      const homeInfo = homesResponse.data[0];
      this.homeId = homeInfo.homeId;
      console.log(`[MirAIe REST] Discovered Home ID: ${this.homeId}`);

      // 2. Parse Devices from spaces
      const discoveredDevices = [];
      if (homeInfo.spaces) {
        for (const space of homeInfo.spaces) {
          if (space.devices) {
            for (const dev of space.devices) {
              const baseTopic = dev.topic?.[0];
              if (baseTopic) {
                discoveredDevices.push({
                  id: dev.deviceId,
                  name: dev.deviceName,
                  friendlyName: dev.deviceName,
                  baseTopic: baseTopic,
                  controlTopic: `${baseTopic}/control`,
                  statusTopic: `${baseTopic}/status`,
                  connectionStatusTopic: `${baseTopic}/connectionStatus`,
                  status: {
                    isOnline: false,
                    temperature: 24,
                    roomTemperature: 24.0,
                    powerMode: 'off',
                    fanMode: 'auto',
                    vSwingMode: 0,
                    hSwingMode: 0,
                    displayMode: 'on',
                    hvacMode: 'auto',
                    presetMode: 'none',
                    convertiMode: 0
                  }
                });
              }
            }
          }
        }
      }

      if (discoveredDevices.length === 0) {
        console.warn('[MirAIe REST] No devices with MQTT topics found.');
        this.devices = [];
        return [];
      }

      // 3. Get Device details (MAC, model, etc)
      const deviceIds = discoveredDevices.map(d => d.id).join(',');
      console.log(`[MirAIe REST] Fetching details for devices: ${deviceIds}...`);

      try {
        let detailsResponse = null;
        let dRetries = 3;
        let dDelay = 1000;
        for (let i = 0; i < dRetries; i++) {
          try {
            detailsResponse = await axios.get(`${APP_BASE_URL}/deviceManagement/devices/deviceId/${deviceIds}`, {
              headers: this.getHeaders(),
              timeout: 10000
            });
            break;
          } catch (err) {
            const isAuth = err.response?.status === 401;
            const isTimeout = err.code === 'ECONNABORTED' || err.message.includes('timeout');
            if ((isAuth || isTimeout) && i < dRetries - 1) {
              console.warn(`[MirAIe REST] Device details fetch failed (${isTimeout ? 'timeout' : 'unauthorized'}). Retrying in ${dDelay}ms...`);
              await new Promise(resolve => setTimeout(resolve, dDelay));
              dDelay += 500;
            } else {
              throw err;
            }
          }
        }

        console.log(`[MirAIe REST] Device details HTTP status: ${detailsResponse.status}`);
        console.log(`[MirAIe REST] Device details raw payload:`, JSON.stringify(detailsResponse.data));

        let detailsList = detailsResponse.data;
        if (detailsList) {
          if (!Array.isArray(detailsList)) {
            console.log('[MirAIe REST] Device details payload is a single object; wrapping in array.');
            detailsList = [detailsList];
          }

          for (const dd of detailsList) {
            const dev = discoveredDevices.find(d => d.id === dd.deviceId);
            if (dev) {
              dev.details = {
                modelName: dd.modelName,
                macAddress: dd.macAddress,
                category: dd.category,
                brand: dd.brand,
                firmwareVersion: dd.firmwareVersion,
                serialNumber: dd.serialNumber,
                modelNumber: dd.modelNumber,
                productSerialNumber: dd.productSerialNumber,
                location: dd.location
              };
              console.log(`[MirAIe REST] Details applied for device ${dd.deviceId}: Model = ${dd.modelName}`);
            } else {
              console.warn(`[MirAIe REST] Found details for device ${dd.deviceId} but it wasn't in discovered devices list.`);
            }
          }
        } else {
          console.warn('[MirAIe REST] Device details payload is empty.');
        }
      } catch (err) {
        console.error('[MirAIe REST] Could not fetch detailed device metadata. Continuing with basic info.');
        console.error('[MirAIe REST] Error message:', err.message);
        if (err.response) {
          console.error('[MirAIe REST] Error response status:', err.response.status);
          console.error('[MirAIe REST] Error response data:', JSON.stringify(err.response.data));
        } else {
          console.error('[MirAIe REST] Error stack:', err.stack);
        }
      }

      this.devices = discoveredDevices;
      return this.devices;
    } catch (error) {
      console.error('[MirAIe REST] Device discovery failed:', error.response?.data || error.message);
      throw error;
    }
  }

  // Fetch live status from REST API (Polling fallback)
  async fetchDeviceStatus(deviceId) {
    if (!this.accessToken) throw new Error('Client not authenticated.');

    try {
      const url = `${APP_BASE_URL}/deviceManagement/devices/${deviceId}/mobile/status`;
      let response = null;
      let retries = 3;
      let delay = 1000;

      for (let i = 0; i < retries; i++) {
        try {
          response = await axios.get(url, {
            headers: this.getHeaders(),
            timeout: 10000
          });
          break; // Success!
        } catch (error) {
          const isAuthError = error.response?.status === 401;
          const isTimeout = error.code === 'ECONNABORTED' || error.message.includes('timeout');
          if ((isAuthError || isTimeout) && i < retries - 1) {
            console.warn(`[MirAIe REST] Status fetch failed (${isTimeout ? 'timeout' : 'unauthorized'}). Retrying in ${delay}ms...`);
            await new Promise(resolve => setTimeout(resolve, delay));
            delay += 500;
          } else {
            throw error;
          }
        }
      }
      
      const status = response.data;

      if (!status || status.ty !== 'AC') {
        return null;
      }

      // Map raw API keys to clean object properties
      const mappedStatus = {
        isOnline: status.onlineStatus === 'true',
        temperature: Math.round(parseFloat(status.actmp || 24)),
        roomTemperature: parseFloat(status.rmtmp || 24),
        powerMode: status.ps || 'off',
        fanMode: status.acfs || 'auto',
        vSwingMode: parseInt(status.acvs || 0),
        hSwingMode: parseInt(status.achs || 0),
        displayMode: status.acdc || 'on',
        hvacMode: status.acmd || 'auto',
        presetMode: status.acpm === 'on' ? 'boost'
          : status.acem === 'on' ? 'eco'
            : status.acec === 'on' ? 'clean'
              : 'none',
        convertiMode: parseInt(status.cnv || 0)
      };

      // Update in-memory state
      const device = this.devices.find(d => d.id === deviceId);
      if (device) {
        device.status = mappedStatus;
      }

      return mappedStatus;
    } catch (error) {
      console.error(`[MirAIe REST] Error fetching status for device ${deviceId}:`, error.message);
      throw error;
    }
  }

  // Connect to MirAIe MQTT broker
  connectMQTT() {
    if (!this.homeId || !this.accessToken) {
      throw new Error('Missing homeId or accessToken. Complete login and discovery first.');
    }

    if (this.mqttClient) {
      console.log('[MirAIe MQTT] Closing existing MQTT client...');
      this.mqttClient.end();
    }

    const brokerUrl = 'mqtts://mqtt.miraie.in:8883';
    console.log(`[MirAIe MQTT] Connecting to ${brokerUrl} using Home ID: ${this.homeId}...`);

    this.mqttClient = mqtt.connect(brokerUrl, {
      username: this.homeId,
      password: this.accessToken,
      rejectUnauthorized: false, // MirAIe broker certificate workaround
      reconnectPeriod: 5000,
      connectTimeout: 30 * 1000
    });

    this.mqttClient.on('connect', () => {
      console.log('[MirAIe MQTT] Broker connection established.');

      // Subscribe to topics for all discovered devices
      for (const dev of this.devices) {
        console.log(`[MirAIe MQTT] Subscribing to: ${dev.statusTopic} & ${dev.connectionStatusTopic}`);
        this.mqttClient.subscribe([dev.statusTopic, dev.connectionStatusTopic]);
      }
    });

    this.mqttClient.on('message', (topic, message) => {
      try {
        const payloadString = message.toString();
        const payload = JSON.parse(payloadString);

        // Find which device this topic belongs to
        const device = this.devices.find(d => d.statusTopic === topic || d.connectionStatusTopic === topic);
        if (!device) return;

        if (topic.endsWith('/status')) {
          // If a control command was recently sent, ignore the AC's immediate
          // echo-back. The echo arrives before the AC has applied the new state
          // and would overwrite the status we just set.
          const lockUntil = this.commandLockUntil.get(device.id) || 0;
          if (Date.now() < lockUntil) {
            console.log(`[MirAIe MQTT] Ignoring echo-back for ${device.name} (command lock active for ${Math.ceil((lockUntil - Date.now()) / 1000)}s more)`);
            return;
          }

          console.log(`[MirAIe MQTT] Live status update for ${device.name}:`, payloadString);

          device.status = {
            isOnline: device.status.isOnline, // Keep online status from connectionStatus
            temperature: Math.round(parseFloat(payload.actmp ?? device.status.temperature)),
            roomTemperature: parseFloat(payload.rmtmp ?? device.status.roomTemperature),
            powerMode: payload.ps ?? device.status.powerMode,
            fanMode: payload.acfs ?? device.status.fanMode,
            vSwingMode: payload.acvs !== undefined ? parseInt(payload.acvs) : device.status.vSwingMode,
            hSwingMode: payload.achs !== undefined ? parseInt(payload.achs) : device.status.hSwingMode,
            displayMode: payload.acdc ?? device.status.displayMode,
            hvacMode: payload.acmd ?? device.status.hvacMode,
            presetMode: payload.acpm === 'on' ? 'boost'
              : payload.acem === 'on' ? 'eco'
                : payload.acec === 'on' ? 'clean'
                  : (payload.acpm === 'off' || payload.acem === 'off' || payload.acec === 'off') ? 'none'
                    : device.status.presetMode,
            convertiMode: payload.cnv !== undefined ? parseInt(payload.cnv) : device.status.convertiMode
          };

          if (this.onStatusUpdate) {
            this.onStatusUpdate(device.id, device.status, payload);
          }
        } else if (topic.endsWith('/connectionStatus')) {
          console.log(`[MirAIe MQTT] Live connection status for ${device.name}:`, payloadString);
          device.status.isOnline = payload.onlineStatus === 'true';

          if (this.onStatusUpdate) {
            this.onStatusUpdate(device.id, device.status);
          }
        }
      } catch (err) {
        console.error('[MirAIe MQTT] Error handling message:', err.message);
      }
    });

    this.mqttClient.on('error', (err) => {
      console.error('[MirAIe MQTT] Client error:', err.message);
    });

    this.mqttClient.on('offline', () => {
      console.warn('[MirAIe MQTT] Client went offline. Reconnecting...');
    });
  }

  // Helper: Publish raw control payload
  publishCommand(controlTopic, commandPayload) {
    if (!this.mqttClient || !this.mqttClient.connected) {
      throw new Error('MQTT client is not connected.');
    }

    const payload = {
      ki: 1,
      cnt: 'an',
      sid: '1',
      ...commandPayload
    };

    console.log(`[MirAIe MQTT] Publishing to ${controlTopic}:`, JSON.stringify(payload));
    this.mqttClient.publish(controlTopic, JSON.stringify(payload), { qos: 1 });

    // Lock out MQTT status echoes for this device for 3 seconds.
    // The AC sends its current status back immediately after receiving a command
    // (before the new state is fully applied), which would overwrite the state
    // we just set. Suppressing those echoes avoids the revert.
    const device = this.devices.find(d => d.controlTopic === controlTopic);
    if (device) {
      this.commandLockUntil.set(device.id, Date.now() + 3000);
      console.log(`[MirAIe MQTT] Command lock applied for device ${device.id} (3s)`);
    }
  }

  // Device Control abstraction methods
  setPower(device, isOn) {
    this.publishCommand(device.controlTopic, { ps: isOn ? 'on' : 'off' });
  }

  setTemperature(device, temp) {
    // Clamp to whole integer as supported by this AC model
    const targetTemp = Math.round(temp);
    this.publishCommand(device.controlTopic, { actmp: targetTemp.toFixed(1) });
  }

  setHVACMode(device, mode) {
    this.publishCommand(device.controlTopic, { acmd: mode });
  }

  setFanMode(device, mode) {
    this.publishCommand(device.controlTopic, { acfs: mode });
  }

  setVSwingMode(device, pos) {
    this.publishCommand(device.controlTopic, { acvs: parseInt(pos) });
  }

  setHSwingMode(device, pos) {
    this.publishCommand(device.controlTopic, { achs: parseInt(pos) });
  }

  setDisplayMode(device, isOn) {
    this.publishCommand(device.controlTopic, { acdc: isOn ? 'on' : 'off' });
  }

  setConvertiMode(device, value) {
    this.publishCommand(device.controlTopic, {
      acem: 'off',
      acpm: 'off',
      cnv: parseInt(value)
    });
  }

  setPresetMode(device, preset) {
    let payload = {};
    if (preset === 'none') {
      payload = { acem: 'off', acpm: 'off', acec: 'off', cnv: 0 };
    } else if (preset === 'eco') {
      payload = { acem: 'on', acpm: 'off', acec: 'off', actmp: '26.0', cnv: 0 };
    } else if (preset === 'boost') {
      payload = { acem: 'off', acpm: 'on', acec: 'off', cnv: 0 };
    } else if (preset === 'clean') {
      payload = { acem: 'off', acpm: 'off', acec: 'on', cnv: 0 };
    }
    this.publishCommand(device.controlTopic, payload);
  }

  // Fetch actual energy consumption from MirAIe cloud API
  async getEnergyConsumption(deviceId, periodType, fromDate, toDate) {
    if (!this.accessToken) throw new Error('Client not authenticated. Call login first.');

    try {
      // periodType values expected by MirAIe: 'Daily', 'Weekly', 'Monthly'
      const url = `${APP_BASE_URL}/powerConsumption/devices/${deviceId}?grain=${periodType}&startDate=${fromDate}&endDate=${toDate}`;
      console.log(`[MirAIe REST] Fetching energy consumption: ${url}`);
      
      const response = await axios.get(url, { headers: this.getHeaders() });
      return response.data; // Expected format: Array of {_key: String, power: Number}
    } catch (error) {
      console.error(`[MirAIe REST] Fetching energy consumption failed for device ${deviceId}:`, error.response?.data || error.message);
      throw error;
    }
  }
}
