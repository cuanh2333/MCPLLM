import React, { useState } from 'react'
import { BookOpen, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react'
import './RAGSources.css'

function RAGSources({ sources }) {
  const [expanded, setExpanded] = useState(false)

  if (!sources || sources.length === 0) {
    return null
  }

  return (
    <div className="rag-sources">
      <div className="sources-header" onClick={() => setExpanded(!expanded)}>
        <BookOpen size={16} />
        <span>Nguồn tham khảo ({sources.length})</span>
        {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
      </div>

      {expanded && (
        <div className="sources-list">
          {sources.map((source, idx) => (
            <div key={idx} className="source-item">
              <div className="source-header">
                <span className="source-number">#{idx + 1}</span>
                <div className="source-meta">
                  <span className="source-title">
                    {source.metadata?.title || source.metadata?.source || 'Unknown'}
                  </span>
                  {source.metadata?.category && (
                    <span className="source-category">{source.metadata.category}</span>
                  )}
                </div>
                <span className="source-score">
                  Score: {(source.hybrid_score || 0).toFixed(3)}
                </span>
              </div>

              <div className="source-content">
                {source.content_snippet}
              </div>

              {source.metadata?.url && (
                <a 
                  href={source.metadata.url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="source-link"
                >
                  <ExternalLink size={12} />
                  Xem nguồn gốc
                </a>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default RAGSources
