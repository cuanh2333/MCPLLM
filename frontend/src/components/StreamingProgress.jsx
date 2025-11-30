import React from 'react'
import { CheckCircle, Loader2, AlertCircle } from 'lucide-react'
import './StreamingProgress.css'

function StreamingProgress({ progress, workflowNodes }) {
  return (
    <div className="streaming-progress">
      <div className="progress-header">
        <Loader2 className="spinner" size={16} />
        <span>Đang xử lý...</span>
      </div>

      {progress && progress.length > 0 && (
        <div className="progress-steps">
          {progress.map((step, idx) => (
            <div key={idx} className="progress-step">
              <CheckCircle size={14} className="step-icon" />
              <span className="step-message">{step.message}</span>
            </div>
          ))}
        </div>
      )}

      {workflowNodes && workflowNodes.length > 0 && (
        <div className="workflow-path">
          <div className="workflow-label">Workflow:</div>
          <div className="workflow-nodes">
            {workflowNodes.map((node, idx) => (
              <React.Fragment key={idx}>
                <span className="workflow-node">{node}</span>
                {idx < workflowNodes.length - 1 && (
                  <span className="workflow-arrow">→</span>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default StreamingProgress
