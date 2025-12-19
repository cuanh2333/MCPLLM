import React, { useState, useEffect } from 'react';

const CronMonitoringSimple = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleStart = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://127.0.0.1:8888/cron/start', {
        method: 'POST',
      });
      if (response.ok) {
        setIsRunning(true);
        alert('Cron started!');
      }
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://127.0.0.1:8888/cron/stop', {
        method: 'POST',
      });
      if (response.ok) {
        setIsRunning(false);
        alert('Cron stopped!');
      }
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '40px', maxWidth: '800px', margin: '0 auto' }}>
      <h1>⏰ Cron Monitoring (Simple)</h1>
      
      <div style={{ 
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        padding: '30px',
        borderRadius: '12px',
        color: 'white',
        marginTop: '20px'
      }}>
        <h2>Status: {isRunning ? '✅ Running' : '⏸️ Stopped'}</h2>
        
        <div style={{ marginTop: '20px' }}>
          {!isRunning ? (
            <button
              onClick={handleStart}
              disabled={loading}
              style={{
                padding: '15px 30px',
                fontSize: '16px',
                background: 'rgba(74, 222, 128, 0.3)',
                border: '2px solid rgba(74, 222, 128, 0.5)',
                borderRadius: '8px',
                color: 'white',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontWeight: 'bold'
              }}
            >
              {loading ? '⏳ Starting...' : '▶️ Start Monitoring'}
            </button>
          ) : (
            <button
              onClick={handleStop}
              disabled={loading}
              style={{
                padding: '15px 30px',
                fontSize: '16px',
                background: 'rgba(248, 113, 113, 0.3)',
                border: '2px solid rgba(248, 113, 113, 0.5)',
                borderRadius: '8px',
                color: 'white',
                cursor: loading ? 'not-allowed' : 'pointer',
                fontWeight: 'bold'
              }}
            >
              {loading ? '⏳ Stopping...' : '⏸️ Stop Monitoring'}
            </button>
          )}
        </div>
      </div>

      <div style={{ marginTop: '30px', padding: '20px', background: '#f8fafc', borderRadius: '8px' }}>
        <h3>ℹ️ How It Works</h3>
        <ul>
          <li>🔄 Analyzes logs every 5 minutes automatically</li>
          <li>⏱️ Monitors last 5 minutes in real-time</li>
          <li>📱 Sends Telegram alerts only when attacks detected</li>
          <li>🛑 Click "Stop" to pause monitoring</li>
        </ul>
      </div>
    </div>
  );
};

export default CronMonitoringSimple;
