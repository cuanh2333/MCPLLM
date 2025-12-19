import React, { useState, useEffect } from 'react';
import './CronScheduler.css';

const CronScheduler = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [error, setError] = useState(null);

  // Fetch initial status
  useEffect(() => {
    fetchStatus();
  }, []);

  const fetchStatus = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8888/cron/status');
      const data = await response.json();
      setStatus(data);
      setIsRunning(data.is_running);
    } catch (err) {
      console.error('Failed to fetch cron status:', err);
    }
  };

  const handleToggle = async () => {
    setLoading(true);
    setError(null);

    try {
      const endpoint = isRunning ? '/cron/stop' : '/cron/start';
      const response = await fetch(`http://127.0.0.1:8888${endpoint}`, {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error('Failed to toggle cron scheduler');
      }

      const data = await response.json();
      
      // Update status
      await fetchStatus();
      
      // Show success message
      console.log(data.message);
    } catch (err) {
      setError(err.message);
      console.error('Error toggling cron:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="cron-scheduler">
      <div className="cron-header">
        <div className="cron-title">
          <span className="cron-icon">⏰</span>
          <h3>Automated Monitoring</h3>
        </div>
        <div className="cron-status-badge">
          <span className={`status-dot ${isRunning ? 'active' : 'inactive'}`}></span>
          <span className="status-text">{isRunning ? 'Active' : 'Inactive'}</span>
        </div>
      </div>

      <div className="cron-body">
        <p className="cron-description">
          Automatically analyze logs every 5 minutes with real-time monitoring.
          Telegram alerts sent only when attacks are detected.
        </p>

        {status && (
          <div className="cron-config">
            <div className="config-item">
              <span className="config-label">Interval:</span>
              <span className="config-value">{status.interval_minutes} minutes</span>
            </div>
            <div className="config-item">
              <span className="config-label">Time Window:</span>
              <span className="config-value">
                {status.earliest_time} to {status.latest_time}
              </span>
            </div>
          </div>
        )}

        <div className="cron-toggle-container">
          <button
            className={`cron-toggle-btn ${isRunning ? 'active' : ''}`}
            onClick={handleToggle}
            disabled={loading}
          >
            {loading ? (
              <span className="loading-spinner">⏳</span>
            ) : (
              <>
                <span className="toggle-icon">{isRunning ? '⏸️' : '▶️'}</span>
                <span className="toggle-text">
                  {isRunning ? 'Stop Monitoring' : 'Start Monitoring'}
                </span>
              </>
            )}
          </button>
        </div>

        {error && (
          <div className="cron-error">
            ⚠️ {error}
          </div>
        )}

        <div className="cron-info">
          <div className="info-item">
            <span className="info-icon">📊</span>
            <span className="info-text">Analyzes logs from last 5 minutes</span>
          </div>
          <div className="info-item">
            <span className="info-icon">🔔</span>
            <span className="info-text">Telegram alerts on attack detection</span>
          </div>
          <div className="info-item">
            <span className="info-icon">📈</span>
            <span className="info-text">Continuous threat monitoring</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CronScheduler;
