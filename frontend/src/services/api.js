// src/services/api.js
// Centralised Axios client for all Flask API calls

import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

const client = axios.create({
  baseURL: BASE_URL,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

// ── Interceptors ─────────────────────────────────────────────────────────────
client.interceptors.response.use(
  (res) => res,
  (err) => {
    const msg =
      err.response?.data?.error ||
      err.message ||
      'An unexpected error occurred'
    return Promise.reject(new Error(msg))
  }
)

// ── API methods ───────────────────────────────────────────────────────────────

/**
 * Submit a URL for phishing analysis.
 * @param {string} url
 * @returns {Promise<Object>} prediction result
 */
export const predictURL = (url) =>
  client.post('/predict', { url }).then((r) => r.data)

/**
 * Fetch scan history.
 * @param {number} limit – max rows (default 50)
 * @returns {Promise<Array>}
 */
export const getHistory = (limit = 50) =>
  client.get('/history', { params: { limit } }).then((r) => r.data)

/**
 * Clear scan history.
 */
export const clearHistory = () =>
  client.delete('/history').then((r) => r.data)

/**
 * Server health check.
 */
export const healthCheck = () =>
  client.get('/health').then((r) => r.data)

/**
 * Aggregate statistics.
 */
export const getStats = () =>
  client.get('/stats').then((r) => r.data)

export default client
