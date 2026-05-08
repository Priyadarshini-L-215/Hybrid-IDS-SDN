/**
 * Centralized API Client Utility
 * 
 * Features:
 * - Retry logic with exponential backoff
 * - Automatic timeout handling
 * - Error normalization
 * - Toast notification support (optional)
 * 
 * Usage:
 * const data = await apiClient.get('/api/alerts');
 * const result = await apiClient.post('/api/block', { ip: '1.2.3.4' });
 */

const DEBUG = import.meta.env.MODE === 'development' && (
  typeof window !== 'undefined' && 
  (new URLSearchParams(window.location.search).get('debug') === 'true' || 
   localStorage.getItem('debug') === 'true')
);

class ApiClient {
  constructor() {
    this.baseURL = '';
    this.defaultTimeout = 30000; // 30 seconds
    this.maxRetries = 3;
    this.baseRetryDelay = 1000; // 1 second
    this.onToast = null; // Callback for toast notifications
  }

  /**
   * Set toast callback for notifications
   */
  setToastCallback(callback) {
    this.onToast = callback;
  }

  /**
   * Show toast notification
   */
  toast(message, type = 'info') {
    if (this.onToast) {
      this.onToast({ message, type });
    } else if (DEBUG) {
      console.log(`[${type.toUpperCase()}] ${message}`);
    }
  }

  /**
   * Exponential backoff retry strategy
   */
  async retry(fn, retries = this.maxRetries) {
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        // Don't retry on client errors (4xx)
        if (error.status >= 400 && error.status < 500) {
          throw error;
        }

        // Last attempt failed
        if (attempt === retries - 1) {
          throw error;
        }

        // Calculate delay with exponential backoff + jitter
        const delay = this.baseRetryDelay * Math.pow(2, attempt) + Math.random() * 100;
        if (DEBUG) console.log(`[API] Retry attempt ${attempt + 1}/${retries} in ${delay}ms`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  /**
   * Execute fetch with timeout
   */
  async fetchWithTimeout(url, options = {}, timeout = this.defaultTimeout) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      // Parse response
      let data = null;
      const contentType = response.headers.get('content-type');

      if (contentType?.includes('application/json')) {
        data = await response.json();
      } else if (contentType?.includes('text')) {
        data = await response.text();
      }

      // Check if response is ok
      if (!response.ok) {
        const error = new Error(
          data?.message || 
          data?.error || 
          `HTTP ${response.status}: ${response.statusText}`
        );
        error.status = response.status;
        error.data = data;
        throw error;
      }

      return data;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error.name === 'AbortError') {
        const timeoutError = new Error(`Request timeout after ${timeout}ms`);
        timeoutError.isTimeout = true;
        throw timeoutError;
      }

      throw error;
    }
  }

  /**
   * GET request
   */
  async get(url, options = {}) {
    return this.retry(() =>
      this.fetchWithTimeout(url, {
        method: 'GET',
        ...options
      })
    );
  }

  /**
   * POST request
   */
  async post(url, body, options = {}) {
    return this.retry(() =>
      this.fetchWithTimeout(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        body: JSON.stringify(body),
        ...options
      })
    );
  }

  /**
   * PUT request
   */
  async put(url, body, options = {}) {
    return this.retry(() =>
      this.fetchWithTimeout(url, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        body: JSON.stringify(body),
        ...options
      })
    );
  }

  /**
   * DELETE request
   */
  async delete(url, options = {}) {
    return this.retry(() =>
      this.fetchWithTimeout(url, {
        method: 'DELETE',
        ...options
      })
    );
  }

  /**
   * Upload file (FormData)
   */
  async uploadFile(url, file, options = {}) {
    const formData = new FormData();
    formData.append('file', file);

    // Add any additional fields
    if (options.formFields) {
      Object.entries(options.formFields).forEach(([key, value]) => {
        formData.append(key, value);
      });
    }

    return this.retry(() =>
      this.fetchWithTimeout(url, {
        method: 'POST',
        body: formData,
        ...options
      }, options.timeout || 60000) // 60s for uploads
    );
  }

  /**
   * Handle API error with user feedback
   */
  handleError(error, context = 'Operation') {
    console.error(`[API Error] ${context}:`, error);

    if (error.isTimeout) {
      this.toast(`${context} timed out. Please try again.`, 'error');
    } else if (error.status === 404) {
      this.toast(`${context}: Resource not found.`, 'error');
    } else if (error.status === 401 || error.status === 403) {
      this.toast(`${context}: Access denied. Please check your credentials.`, 'error');
    } else if (error.status >= 500) {
      this.toast(`${context}: Server error. Please try again later.`, 'error');
    } else if (error.message) {
      this.toast(`${context}: ${error.message}`, 'error');
    } else {
      this.toast(`${context} failed. Please try again.`, 'error');
    }

    throw error;
  }
}

// Export singleton instance
export const apiClient = new ApiClient();

export default apiClient;
