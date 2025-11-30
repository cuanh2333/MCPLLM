import React, { useState, useEffect } from 'react';
import './CronMonitoring.css';

const CronMonitoring = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [statistics, setStatistics] = useState(null);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);

  // Fetch initial status
  useEffect(() => {
    fetchStatus();
    fetchStatistics();
  }, []);

  // Auto-refresh statistics
  useEffect(() => {
    if (!isRunning) return;
    
    const interval = setInterval(() => {
      fetchStatistics();
    }, 30000);
    
    return () => clearInterval(interval);
  }, [isRunning]);

  const fetchStatus = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8000/cron/status');
      const data = await response.json();
      setStatus(data);
      setIsRunning(data.is_running);
    } catch (err) {
      console.error('Failed to fetch cron status:', err);
    }
  };

  const fetchStatistics = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8000/statistics');
      const data = await response.json();
      setStatistics(data);
      setLastUpdate(new Date());
    } catch (err) {
      console.error('Failed to fetch statistics:', err);
    }
  };

  const handleStart = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('http://127.0.0.1:8000/cron/start', {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error('Failed to start cron scheduler');
      }

      const data = await response.json();
      console.log(data.message);
      
      await fetchStatus();
      await fetchStatistics();
    } catch (err) {
      setError(err.message);
      console.error('Error starting cron:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('http://127.0.0.1:8000/cron/stop', {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error('Failed to stop cron scheduler');
      }

      const data = await response.json();
      console.log(data.message);
      
      await fetchStatus();
    } catch (err) {
      setError(err.message);
      console.error('Error stopping cron:', err);
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (date) => {
    if (!date) return 'Never';
    return date.toLocaleTimeString('vi-VN');
  };

  return (
    <div className="cron-monitoring">
      {/* Header with Status */}
      <div className="cron-header-section">
        <div className="cron-title-area">
          <h1>
            <span className="title-icon">⏰</span>
            Automated Monitoring
          </h1>
          <p className="subtitle">Continuous threat detection with sliding window analysis</p>
        </div>

        <div className="cron-status-card">
          <div className="status-indicator">
            <span className={`status-dot ${isRunning ? 'active' : 'inactive'}`}></span>
            <div className="status-info">
              <span className="status-label">Status</span>
              <span className="status-value">{isRunning ? 'Running' : 'Stopped'}</span>
            </div>
          </div>

          {status && (
            <div className="status-details">
              <div className="detail-item">
                <span className="detail-label">Interval</span>
                <span className="detail-value">{status.interval_minutes} min</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Window</span>
                <span className="detail-value">{status.earliest_time} → {status.latest_time}</span>
              </div>
            </div>
          )}

          <div className="control-buttons">
            {!isRunning ? (
              <button
                className="btn-start"
                onClick={handleStart}
                disabled={loading}
              >
                {loading ? '⏳ Starting...' : '▶️ Start Monitoring'}
              </button>
            ) : (
              <button
                className="btn-stop"
                onClick={handleStop}
                disabled={loading}
              >
                {loading ? '⏳ Stopping...' : '⏸️ Stop Monitoring'}
              </button>
            )}
          </div>

          {error && (
            <div className="error-message">
              ⚠️ {error}
            </div>
          )}
        </div>
      </div>

      {/* Statistics Dashboard */}
      {statistics && (
        <div className="statistics-dashboard">
          {/* Summary Cards */}
          <div className="summary-cards">
            <div className="stat-card total">
              <div className="card-icon">📊</div>
              <div className="card-content">
                <div className="card-value">{statistics.total_events || 0}</div>
                <div className="card-label">Total Events</div>
              </div>
            </div>

            <div className="stat-card attacks">
              <div className="card-icon">🚨</div>
              <div className="card-content">
                <div className="card-value">{statistics.total_attack_events || 0}</div>
                <div className="card-label">Attack Events</div>
              </div>
            </div>

            <div className="stat-card rate">
              <div className="card-icon">📈</div>
              <div className="card-content">
                <div className="card-value">
                  {statistics.total_events > 0
                    ? ((statistics.total_attack_events / statistics.total_events) * 100).toFixed(1)
                    : 0}%
                </div>
                <div className="card-label">Attack Rate</div>
              </div>
            </div>

            <div className="stat-card update">
              <div className="card-icon">🕐</div>
              <div className="card-content">
                <div className="card-value">{formatTime(lastUpdate)}</div>
                <div className="card-label">Last Update</div>
              </div>
            </div>
          </div>

          {/* IP Details Table */}
          {statistics.ip_details && statistics.ip_details.length > 0 && (
            <div className="data-section">
              <h2>🌐 Attack Sources by IP</h2>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>IP Address</th>
                      <th>Total Events</th>
                      <th>Attack Events</th>
                      <th>Attack Rate</th>
                      <th>Top Attack Type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {statistics.ip_details.map((ip, index) => (
                      <tr key={index}>
                        <td className="ip-cell">
                          <span className="ip-address">{ip.ip}</span>
                        </td>
                        <td>{ip.total_events}</td>
                        <td className="attack-count">{ip.attack_events}</td>
                        <td>
                          <span className={`rate-badge ${ip.attack_rate > 50 ? 'high' : ip.attack_rate > 20 ? 'medium' : 'low'}`}>
                            {ip.attack_rate.toFixed(1)}%
                          </span>
                        </td>
                        <td>
                          {ip.top_attack_type && (
                            <span className="attack-badge">{ip.top_attack_type.toUpperCase()}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Trend Chart */}
          {statistics.trend_data && statistics.trend_data.length > 0 && (
            <div className="data-section">
              <h2>📈 Event Trend (Last 24 Hours)</h2>
              <div className="trend-chart">
                {statistics.trend_data.map((point, index) => {
                  const maxEvents = Math.max(...statistics.trend_data.map(p => p.total_events));
                  const height = maxEvents > 0 ? (point.total_events / maxEvents) * 100 : 0;
                  const attackHeight = maxEvents > 0 ? (point.attack_events / maxEvents) * 100 : 0;
                  
                  return (
                    <div key={index} className="trend-bar-group">
                      <div className="trend-bars">
                        <div 
                          className="trend-bar total" 
                          style={{ height: `${height}%` }}
                          title={`Total: ${point.total_events}`}
                        ></div>
                        <div 
                          className="trend-bar attack" 
                          style={{ height: `${attackHeight}%` }}
                          title={`Attacks: ${point.attack_events}`}
                        ></div>
                      </div>
                      <div className="trend-label">{point.hour}h</div>
                    </div>
                  );
                })}
              </div>
              <div className="trend-legend">
                <div className="legend-item">
                  <span className="legend-color total"></span>
                  <span>Total Events</span>
                </div>
                <div className="legend-item">
                  <span className="legend-color attack"></span>
                  <span>Attack Events</span>
                </div>
              </div>
            </div>
          )}

          {/* Info Box */}
          <div className="info-box">
            <h3>ℹ️ How It Works</h3>
            <ul>
              <li>🔄 Analyzes logs every 5 minutes automatically</li>
              <li>⏱️ Uses sliding window: 7 hours ago (5-minute window)</li>
              <li>📱 Sends Telegram alerts only when attacks detected</li>
              <li>📊 Statistics update in real-time</li>
              <li>🛑 Click "Stop" to pause monitoring</li>
            </ul>
          </div>
        </div>
      )}

      {!statistics && isRunning && (
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Waiting for first analysis results...</p>
        </div>
      )}

      {!statistics && !isRunning && (
        <div className="empty-state">
          <div className="empty-icon">⏰</div>
          <h3>Monitoring Not Started</h3>
          <p>Click "Start Monitoring" to begin automated threat detection</p>
        </div>
      )}
    </div>
  );
};

export default CronMonitoring;
