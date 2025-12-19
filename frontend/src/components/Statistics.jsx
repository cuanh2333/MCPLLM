import React, { useState, useEffect } from 'react'
import { Activity, AlertTriangle, ArrowUp } from 'lucide-react'
import axios from 'axios'
import './Statistics.css'

function Statistics() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [sourceType, setSourceType] = useState('all')
  const [showScrollTop, setShowScrollTop] = useState(false)
  const [selectedReport, setSelectedReport] = useState('latest')
  const [reportsBySource, setReportsBySource] = useState({})

  useEffect(() => {
    if (sourceType === 'file') {
      // For file uploads, fetch available reports
      fetchAvailableReports()
    } else {
      // For cron/query/all, fetch aggregated statistics
      fetchStatistics()
    }
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      if (sourceType === 'file') {
        fetchAvailableReports()
      } else {
        fetchStatistics()
      }
    }, 30000)
    
    return () => clearInterval(interval)
  }, [sourceType])
  
  useEffect(() => {
    const handleScroll = () => {
      setShowScrollTop(window.scrollY > 100)
    }
    
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])
  
  useEffect(() => {
    if (sourceType === 'file' && selectedReport && selectedReport !== '') {
      fetchFileStatistics(selectedReport)
    }
  }, [selectedReport])

  const fetchAvailableReports = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:8888/statistics/reports')
      const grouped = response.data.reports_by_source || {}
      setReportsBySource(grouped)
      
      // Set default report for file mode
      if (sourceType === 'file' && grouped.file && grouped.file.length > 0) {
        setSelectedReport(grouped.file[0].id)
      }
    } catch (err) {
      console.error('Error fetching reports:', err)
    }
  }

  const fetchStatistics = async () => {
    setLoading(true)
    setError(null)
    try {
      // Use aggregated statistics from metadata (for cron/query/all)
      const response = await axios.get(`http://127.0.0.1:8888/statistics/aggregated?source=${sourceType}`)
      console.log('Aggregated statistics data:', response.data)
      console.log('Total events:', response.data.total_events)
      console.log('Attack events:', response.data.total_attack_events)
      console.log('IP details:', response.data.ip_details)
      console.log('IP details length:', response.data.ip_details?.length)
      setStats(response.data)
    } catch (err) {
      console.error('Error fetching statistics:', err)
      setError('Không thể tải dữ liệu thống kê')
    } finally {
      setLoading(false)
    }
  }
  
  const fetchFileStatistics = async (reportId) => {
    setLoading(true)
    setError(null)
    try {
      // For file uploads, fetch individual report statistics
      const response = await axios.get(`http://127.0.0.1:8888/statistics?report=${reportId}&source=file`)
      console.log('File statistics data:', response.data)
      setStats(response.data)
    } catch (err) {
      console.error('Error fetching file statistics:', err)
      setError('Không thể tải dữ liệu thống kê')
    } finally {
      setLoading(false)
    }
  }

  const handleSourceChange = (newSource) => {
    setSourceType(newSource)
    if (newSource === 'file') {
      // Reset selected report when switching to file mode
      setSelectedReport('')
    }
  }

  const currentReports = reportsBySource[sourceType] || []

  if (loading) {
    return (
      <div className="statistics-container">
        <div className="loading-stats">
          <Activity className="spinner" size={48} />
          <p>Đang tải thống kê...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="statistics-container">
        <div className="error-stats">
          <AlertTriangle size={48} color="#ef4444" />
          <p>{error}</p>
          <button onClick={fetchStatistics} className="retry-btn">Thử lại</button>
        </div>
      </div>
    )
  }

  if (!stats) return null

  // Check if we have any data - must check both are numbers and > 0
  const hasData = (typeof stats.total_events === 'number' && stats.total_events > 0) || 
                  (typeof stats.total_attack_events === 'number' && stats.total_attack_events > 0)
  
  console.log('hasData:', hasData, 'total_events:', stats.total_events, 'ip_details:', stats.ip_details)

  const attackPercentage = hasData && stats.total_events > 0 
    ? ((stats.total_attack_events / stats.total_events) * 100).toFixed(0)
    : 0

  const cleanPercentage = hasData && stats.total_events > 0 
    ? (100 - attackPercentage).toFixed(0) 
    : 0

  return (
    <div className="statistics-container">
      <div className="stats-header">
        <h1>Bảng Điều Khiển Phân Tích Tấn Công & An Ninh IP</h1>
        <div className="header-controls">
          <select 
            className="source-selector" 
            value={sourceType}
            onChange={(e) => handleSourceChange(e.target.value)}
          >
            <option value="all">📊 Tất Cả (Tổng hợp)</option>
            <option value="cron">⏰ Cron Job (Tổng hợp)</option>
            <option value="query">💬 User Query (Tổng hợp)</option>
            <option value="file">📁 File Upload (Chọn file)</option>
          </select>
          
          {/* Show file selector only for file mode */}
          {sourceType === 'file' && (
            <select 
              className="report-selector" 
              value={selectedReport}
              onChange={(e) => setSelectedReport(e.target.value)}
              disabled={currentReports.length === 0}
            >
              {currentReports.length > 0 ? (
                currentReports.map((report) => (
                  <option key={report.id} value={report.id}>
                    {report.label}
                  </option>
                ))
              ) : (
                <option value="">Chưa có file nào</option>
              )}
            </select>
          )}
          
          <button className="refresh-btn" onClick={() => sourceType === 'file' ? fetchAvailableReports() : fetchStatistics()}>
            Làm Mới
          </button>
        </div>
      </div>
      
      {/* Source Breakdown Summary - only for aggregated views */}
      {sourceType !== 'file' && stats && stats.source_breakdown && stats.source_breakdown.length > 0 && (
        <div className="source-breakdown-banner">
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
            <strong>📊 Tổng hợp: {stats.total_runs} lần phân tích | {stats.total_events} events | {stats.total_attack_events} attacks</strong>
            {stats.source_breakdown.map((item, idx) => (
              <span key={idx} style={{ 
                background: 'rgba(59, 130, 246, 0.2)', 
                padding: '4px 12px', 
                borderRadius: '6px',
                fontSize: '0.9rem'
              }}>
                {item.source_type === 'cron' && '⏰'}
                {item.source_type === 'query' && '💬'}
                {item.source_type === 'file' && '📁'}
                {' '}{item.source_type.toUpperCase()}: {item.runs} lần, {item.total_events} events
              </span>
            ))}
          </div>
        </div>
      )}

      {/* No data message */}
      {!hasData && (
        <div className="info-banner">
          ℹ️ Chưa có dữ liệu cho nguồn này. Vui lòng chạy phân tích hoặc chọn nguồn khác.
        </div>
      )}

      {/* Warning if no AbuseIPDB data */}
      {hasData && stats.ip_details && stats.ip_details.length > 0 && 
       stats.ip_details.some(ip => ip.status_text.includes('Dựa trên loại tấn công')) && (
        <div className="warning-banner">
          ⚠️ Một số IP chưa có dữ liệu từ AbuseIPDB. Đánh giá hiện tại dựa trên loại tấn công. 
          Chạy phân tích đầy đủ để lấy thông tin reputation từ AbuseIPDB.
        </div>
      )}

      {hasData && (
      <div className="stats-layout">
        {/* Left Section - Pie Chart */}
        <div className="pie-section">
          <h2>Tỷ Lệ Tấn Công vs. Không Tấn Công</h2>
          <div className="pie-chart-wrapper">
            <svg viewBox="0 0 200 200" className="pie-chart">
              <PieSlice 
                percentage={parseFloat(cleanPercentage)} 
                color="#10b981" 
                offset={0}
              />
              <PieSlice 
                percentage={parseFloat(attackPercentage)} 
                color="#ef4444" 
                offset={parseFloat(cleanPercentage)}
              />
            </svg>
            <div className="pie-center-text">
              <div className="pie-percentage">{cleanPercentage}%</div>
              <div className="pie-label">Sạch</div>
            </div>
          </div>
          <div className="pie-legend">
            <div className="legend-item">
              <span className="legend-dot green"></span>
              <span>Không Tấn Công</span>
            </div>
            <div className="legend-item">
              <span className="legend-dot red"></span>
              <span>Tấn Công</span>
            </div>
          </div>
        </div>

        {/* Right Section - Stats Cards */}
        <div className="stats-cards-section">
          <div className="stat-card-row">
            <div className="stat-card">
              <div className="stat-card-header">Tỷ Lệ Không Tấn Công</div>
              <div className="stat-card-value">{cleanPercentage}%</div>
              <div className="stat-card-indicator green">
                <span className="indicator-dot"></span>
                Sạch
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-card-header">Tỷ Lệ Tấn Công</div>
              <div className="stat-card-value">{attackPercentage}%</div>
              <div className="stat-card-progress">
                <div 
                  className="progress-bar" 
                  style={{ width: `${attackPercentage}%` }}
                ></div>
              </div>
            </div>
          </div>

          <div className="stat-card-row">
            <div className="stat-card">
              <div className="stat-card-header">Số Lượng Tấn Công</div>
              <div className="stat-card-value">{stats.total_attack_events}</div>
              <div className="stat-card-indicator red">
                <span className="indicator-dot"></span>
                Tổng số events tấn công
              </div>
            </div>
            
            <div className="stat-card">
              <div className="stat-card-header">Tổng Số Lần Phân Tích</div>
              <div className="stat-card-value">{stats.total_runs || 0}</div>
              <div className="stat-card-indicator">
                <span className="indicator-dot"></span>
                {stats.runs_with_attacks || 0} lần có tấn công
              </div>
            </div>
          </div>
        </div>
      </div>
      )}

      {/* IP Data Table */}
      {hasData && (
      <div className="data-table-section">
        <div className="table-header">
          <h2>Dữ Liệu Chi Tiết IP</h2>
          <div className="table-tabs">
            <button className="table-tab active">Tất Cả</button>
          </div>
        </div>

        <table className="ip-table">
          <thead>
            <tr>
              <th>Địa Chỉ IP</th>
              <th>Kỹ Thuật Tấn Công</th>
              <th>Số Lần</th>
              <th>Trạng Thái (AbuseIPDB)</th>
              <th>Mức Độ</th>
            </tr>
          </thead>
          <tbody>
            {stats.ip_details && stats.ip_details.length > 0 ? (
              stats.ip_details.map((ip, idx) => (
                <tr key={idx}>
                  <td className="ip-cell">{ip.ip}</td>
                  <td className="tech-cell">{ip.attack_type}</td>
                  <td className="count-cell">{ip.count || '-'}</td>
                  <td>
                    <span className={`status-badge status-${ip.status}`}>
                      {ip.status_text || ip.status}
                    </span>
                  </td>
                  <td>
                    <span className={`severity-badge severity-${Math.floor(parseFloat(ip.severity))}`}>
                      {parseFloat(ip.severity).toFixed(1)}
                    </span>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '2rem', color: '#8b92a7' }}>
                  Chưa có dữ liệu IP. {sourceType === 'file' ? 'Vui lòng chọn file có chứa dữ liệu tấn công.' : 'Chưa có lần phân tích nào phát hiện tấn công.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      )}
      
      {/* Scroll to Top Button - Always visible */}
      <button 
        className="scroll-to-top"
        onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
        aria-label="Scroll to top"
        style={{ opacity: showScrollTop ? 1 : 0.5 }}
      >
        <ArrowUp size={24} />
      </button>
    </div>
  )
}

// Pie Chart Slice Component
function PieSlice({ percentage, color, offset }) {
  const radius = 70
  const circumference = 2 * Math.PI * radius
  const strokeDasharray = `${(percentage / 100) * circumference} ${circumference}`
  const strokeDashoffset = -((offset / 100) * circumference)

  return (
    <circle
      cx="100"
      cy="100"
      r={radius}
      fill="transparent"
      stroke={color}
      strokeWidth="60"
      strokeDasharray={strokeDasharray}
      strokeDashoffset={strokeDashoffset}
      transform="rotate(-90 100 100)"
    />
  )
}

// Trend Chart Component
function TrendChart({ data, color }) {
  if (!data || data.length === 0) {
    data = [3, 5, 2, 8, 6, 9, 4, 7, 5, 6]
  }

  const max = Math.max(...data)
  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * 100
    const y = 100 - (value / max) * 80
    return `${x},${y}`
  }).join(' ')

  return (
    <svg viewBox="0 0 100 40" className="trend-chart" preserveAspectRatio="none">
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="2"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}

export default Statistics
