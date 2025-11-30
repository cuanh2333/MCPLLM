import React from 'react'
import { Download } from 'lucide-react'
import './DataTable.css'

function DataTable({ data, filename }) {
  if (!data || !data.rows || data.rows.length === 0) {
    return null
  }

  const handleDownload = () => {
    // Convert to CSV
    const headers = data.columns.join(',')
    const rows = data.rows.map(row => 
      data.columns.map(col => row[col]).join(',')
    ).join('\n')
    
    const csv = `${headers}\n${rows}`
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename || 'data.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="data-table-container">
      <div className="data-table-header">
        <div className="file-icon">📊</div>
        <div className="file-info">
          <h4>{filename || 'data.csv'}</h4>
          <p>{data.rows.length} rows detected...</p>
        </div>
      </div>

      <div className="data-table-preview">
        <table>
          <thead>
            <tr>
              <th>#</th>
              {data.columns.map((col, idx) => (
                <th key={idx}>{col}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.rows.slice(0, 3).map((row, idx) => (
              <tr key={idx}>
                <td>{idx + 1}</td>
                {data.columns.map((col, colIdx) => (
                  <td key={colIdx}>{row[col]}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <button className="download-full-btn" onClick={handleDownload}>
        <Download size={16} />
        Download Full CSV
      </button>
    </div>
  )
}

export default DataTable
