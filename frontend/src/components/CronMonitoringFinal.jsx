import React, { useState, useEffect } from 'react';
import './CronMonitoring.css';

const CronMonitoringFinal = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [statistics, setStatistics] = useState(null);
  const [error, setError] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);

  useEffect(() => {
    fetchStatus();
    fetchStatistics();
  }, []);

  useEffect(() => {
    if (!isRunning) return;
    
    const interval = setInterval(() => {
      fetchStatistics();
    }, 30000);
    
    return () => clearInterval(interval);
  }, [isRunning]);

  const fetchStatus = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8888/cron/status');
      const data = await response.json();
      setIsRunning(data.is_running);
    } catch (err) {
      console.error('Failed to fetch cron status:', err);
    }
  };

  const fetchStatistics = async () => {
    try {
      // Fetch cron-specific statistics (aggregated from all cron runs)
      const response = await fetch('http://127.0.0.1:8888/cron/statistics');
      const data = await response.json();
      
      // If no cron data, set empty statistics
      if (data.total_events === 0 && data.total_attack_events === 0) {
        setStatistics({
          total_events: 0,
          total_attack_events: 0,
          ip_details: [],
          trend_data: [],
          attack_trend: []
        });
      } else {
        setStatistics(data);
      }
      
      setLastUpdate(new Date());
    } catch (err) {
      console.error('Failed to fetch statistics:', err);
      // Set empty statistics on error
      setStatistics({
        total_events: 0,
        total_attack_events: 0,
        ip_details: [],
        trend_data: [],
        attack_trend: []
      });
    }
  };

  const handleStart = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('http://127.0.0.1:8888/cron/start', {
        method: 'POST',
      });
      if (response.ok) {
        await fetchStatus();
        await fetchStatistics();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('http://127.0.0.1:8888/cron/stop', {
        method: 'POST',
      });
      if (response.ok) {
        await fetchStatus();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (date) => {
    if (!date) return 'Never';
    return date.toLocaleTimeString('vi-VN');
  };

  return (
    <div style={{
      background: '#f5f7fa',
      minHeight: '100vh',
      width: '100%',
      position: 'absolute',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      overflowY: 'auto',
      padding: '24px'
    }}>
    <div className="cron-monitoring">
      {/* Control Panel */}
      <div style={{
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        padding: '30px',
        borderRadius: '12px',
        color: 'white',
        marginBottom: '24px'
      }}>
        <h1 style={{ margin: '0 0 20px 0', fontSize: '28px' }}>
          ⏰ Automated Monitoring
        </h1>
        
        <div style={{ marginBottom: '20px' }}>
          <div style={{ fontSize: '18px', marginBottom: '8px' }}>
            Status: {isRunning ? '✅ Running' : '⏸️ Stopped'}
          </div>
          <div style={{ fontSize: '14px', opacity: 0.9 }}>
            Interval: 5 minutes | Window: -5m to now
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button
            onClick={async () => {
              try {
                const response = await fetch('http://127.0.0.1:8888/cron/reload', { method: 'POST' });
                const data = await response.json();
                alert(`✅ ${data.message}\nNew config: ${data.config.earliest_time} to ${data.config.latest_time}`);
                fetchStatus(); // Refresh status
              } catch (err) {
                alert(`❌ Failed to reload config: ${err.message}`);
              }
            }}
            disabled={loading}
            style={{
              padding: '10px 20px',
              backgroundColor: '#17a2b8',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '14px'
            }}
          >
            🔄 Reload Config
          </button>
          
          {!isRunning ? (
            <button
              onClick={handleStart}
              disabled={loading}
              style={{
                padding: '14px 28px',
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
                padding: '14px 28px',
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
          
          <button
            onClick={fetchStatistics}
            style={{
              padding: '14px 28px',
              fontSize: '16px',
              background: 'rgba(255, 255, 255, 0.2)',
              border: '2px solid rgba(255, 255, 255, 0.3)',
              borderRadius: '8px',
              color: 'white',
              cursor: 'pointer',
              fontWeight: 'bold'
            }}
          >
            🔄 Refresh
          </button>
        </div>

        {error && (
          <div style={{
            marginTop: '16px',
            padding: '12px',
            background: 'rgba(248, 113, 113, 0.3)',
            border: '1px solid rgba(248, 113, 113, 0.5)',
            borderRadius: '6px'
          }}>
            ⚠️ {error}
          </div>
        )}
      </div>

      {/* Statistics Dashboard */}
      {statistics && (
        <div>
          {/* Summary Cards */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '20px',
            marginBottom: '24px'
          }}>
            <div style={{
              background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              padding: '24px',
              borderRadius: '12px',
              boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
              color: 'white'
            }}>
              <div style={{ fontSize: '14px', opacity: 0.9, marginBottom: '8px' }}>
                📊 TỔNG SỰ KIỆN
              </div>
              <div style={{ fontSize: '32px', fontWeight: 'bold' }}>
                {statistics.total_events || 0}
              </div>
            </div>

            <div style={{
              background: statistics.total_attack_events > 0 
                ? 'linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%)'
                : 'linear-gradient(135deg, #10ac84 0%, #00d2d3 100%)',
              padding: '24px',
              borderRadius: '12px',
              boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
              color: 'white'
            }}>
              <div style={{ fontSize: '14px', opacity: 0.9, marginBottom: '8px' }}>
                {statistics.total_attack_events > 0 ? '🚨 CUỘC TẤN CÔNG' : '✅ AN TOÀN'}
              </div>
              <div style={{ fontSize: '32px', fontWeight: 'bold' }}>
                {statistics.total_attack_events || 0}
              </div>
              <div style={{ fontSize: '12px', opacity: 0.8, marginTop: '4px' }}>
                {statistics.total_attack_events > 0 ? 'Phát hiện tấn công!' : 'Không có tấn công'}
              </div>
            </div>

            <div style={{
              background: (() => {
                const rate = statistics.total_events > 0 
                  ? (statistics.total_attack_events / statistics.total_events) * 100 
                  : 0;
                if (rate === 0) return 'linear-gradient(135deg, #10ac84 0%, #00d2d3 100%)';
                if (rate < 10) return 'linear-gradient(135deg, #f39c12 0%, #f1c40f 100%)';
                return 'linear-gradient(135deg, #e74c3c 0%, #c0392b 100%)';
              })(),
              padding: '24px',
              borderRadius: '12px',
              boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
              color: 'white'
            }}>
              <div style={{ fontSize: '14px', opacity: 0.9, marginBottom: '8px' }}>
                📈 TỶ LỆ TẤN CÔNG
              </div>
              <div style={{ fontSize: '32px', fontWeight: 'bold' }}>
                {statistics.total_events > 0
                  ? ((statistics.total_attack_events / statistics.total_events) * 100).toFixed(1)
                  : 0}%
              </div>
              <div style={{ fontSize: '12px', opacity: 0.8, marginTop: '4px' }}>
                {statistics.total_events > 0 
                  ? `${statistics.total_attack_events}/${statistics.total_events} events`
                  : 'Chưa có dữ liệu'}
              </div>
            </div>

            <div style={{
              background: 'white',
              padding: '24px',
              borderRadius: '12px',
              boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
            }}>
              <div style={{ fontSize: '14px', color: '#64748b', marginBottom: '8px' }}>
                LAST UPDATE
              </div>
              <div style={{ fontSize: '20px', fontWeight: 'bold', color: '#1e293b' }}>
                {formatTime(lastUpdate)}
              </div>
            </div>
          </div>

          {/* IP Details Table - Only show if there are attacks */}
          {statistics.total_attack_events > 0 && statistics.ip_details && statistics.ip_details.length > 0 && (
            <div style={{
              background: 'white',
              padding: '24px',
              borderRadius: '12px',
              boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
              marginBottom: '24px'
            }}>
              <h2 style={{ margin: '0 0 20px 0', fontSize: '20px' }}>
                🌐 Top Attack Sources
              </h2>
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #e2e8f0' }}>
                      <th style={{ padding: '12px', textAlign: 'left', fontSize: '12px', color: '#64748b' }}>IP ADDRESS</th>
                      <th style={{ padding: '12px', textAlign: 'left', fontSize: '12px', color: '#64748b' }}>ATTACKS</th>
                      <th style={{ padding: '12px', textAlign: 'left', fontSize: '12px', color: '#64748b' }}>TYPES</th>
                      <th style={{ padding: '12px', textAlign: 'left', fontSize: '12px', color: '#64748b' }}>STATUS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {statistics.ip_details.slice(0, 10).map((ip, index) => (
                      <tr key={index} style={{ borderBottom: '1px solid #e2e8f0' }}>
                        <td style={{ padding: '14px', fontFamily: 'monospace', fontWeight: '600' }}>
                          {ip.ip}
                        </td>
                        <td style={{ padding: '14px', color: '#ef4444', fontWeight: '600' }}>
                          {ip.count}
                        </td>
                        <td style={{ padding: '14px', fontSize: '13px' }}>
                          {ip.attack_types}
                        </td>
                        <td style={{ padding: '14px' }}>
                          <span style={{
                            padding: '4px 12px',
                            borderRadius: '12px',
                            fontSize: '12px',
                            fontWeight: '600',
                            background: ip.status === 'critical' ? '#fee2e2' : 
                                       ip.status === 'high' ? '#fef3c7' : '#dcfce7',
                            color: ip.status === 'critical' ? '#dc2626' :
                                   ip.status === 'high' ? '#d97706' : '#16a34a'
                          }}>
                            {ip.status_text || ip.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Info Box */}
          <div style={{
            background: '#ffffff',
            padding: '24px',
            borderRadius: '12px',
            border: '2px solid #e2e8f0',
            boxShadow: '0 2px 8px rgba(0,0,0,0.08)'
          }}>
            <h3 style={{ 
              margin: '0 0 16px 0', 
              fontSize: '18px', 
              color: '#0f172a', 
              fontWeight: '700',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              <span style={{ fontSize: '20px' }}>ℹ️</span> Cách Hoạt Động
            </h3>
            <ul style={{ 
              margin: 0, 
              paddingLeft: '24px', 
              lineHeight: '2', 
              color: '#1e293b',
              fontSize: '15px'
            }}>
              <li style={{ marginBottom: '8px' }}><strong>🔄</strong> Tự động phân tích log mỗi 5 phút</li>
              <li style={{ marginBottom: '8px' }}><strong>⏱️</strong> Giám sát thời gian thực (5 phút gần nhất)</li>
              <li style={{ marginBottom: '8px' }}><strong>📱</strong> Gửi cảnh báo Telegram khi phát hiện tấn công</li>
              <li style={{ marginBottom: '8px' }}><strong>📊</strong> Thống kê tự động cập nhật mỗi 30 giây</li>
              <li><strong>🛑</strong> Nhấn "Stop" để tạm dừng giám sát</li>
            </ul>
          </div>


        </div>
      )}

      {!statistics && !isRunning && (
        <div style={{ textAlign: 'center', padding: '60px 20px', color: '#64748b' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>⏰</div>
          <h3 style={{ fontSize: '20px', marginBottom: '8px' }}>Chưa Có Dữ Liệu</h3>
          <p>Bắt đầu giám sát để thu thập thống kê</p>
        </div>
      )}
      
      {!statistics && isRunning && (
        <div style={{ textAlign: 'center', padding: '60px 20px', color: '#64748b' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>⏳</div>
          <h3 style={{ fontSize: '20px', marginBottom: '8px' }}>Đang Chờ Phân Tích Đầu Tiên</h3>
          <p>Cron sẽ chạy mỗi 5 phút. Kết quả đầu tiên sắp có...</p>
        </div>
      )}
    </div>
    </div>
  );
};

export default CronMonitoringFinal;
