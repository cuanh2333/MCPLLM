import React, { useState, useRef, useEffect } from 'react'
import { Send, Paperclip, FileText, Download, Loader2, X, MessageSquare, BarChart3, Clock } from 'lucide-react'
import axios from 'axios'
import DataTable from './components/DataTable'
import RAGSources from './components/RAGSources'
import Statistics from './components/Statistics'
import CronMonitoring from './components/CronMonitoringFinal'
import './App.css'

function App() {
  const [activeView, setActiveView] = useState('chat') // 'chat', 'statistics', or 'monitoring'
  
  // Chat sessions management
  const [chatSessions, setChatSessions] = useState(() => {
    try {
      const saved = localStorage.getItem('chatSessions')
      return saved ? JSON.parse(saved) : []
    } catch (e) {
      console.error('Failed to load chat sessions:', e)
      return []
    }
  })
  
  const [currentSessionId, setCurrentSessionId] = useState(() => {
    try {
      const saved = localStorage.getItem('currentSessionId')
      return saved || null
    } catch (e) {
      return null
    }
  })
  
  // Current chat messages (derived from current session)
  const [messages, setMessages] = useState(() => {
    if (currentSessionId) {
      const session = chatSessions.find(s => s.id === currentSessionId)
      return session ? session.messages : []
    }
    return []
  })
  
  const [inputText, setInputText] = useState('')
  const [uploadedFile, setUploadedFile] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [chatHistory, setChatHistory] = useState([]) // Deprecated, keeping for compatibility
  const [sendTelegram, setSendTelegram] = useState(false)
  const [showMenu, setShowMenu] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
  const messagesEndRef = useRef(null)
  const fileInputRef = useRef(null)

  const scrollToBottom = () => {
    setTimeout(() => {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, 100)
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  // Save chat sessions to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('chatSessions', JSON.stringify(chatSessions))
    } catch (e) {
      console.error('Failed to save chat sessions:', e)
    }
  }, [chatSessions])

  // Save current session ID
  useEffect(() => {
    try {
      if (currentSessionId) {
        localStorage.setItem('currentSessionId', currentSessionId)
      }
    } catch (e) {
      console.error('Failed to save current session ID:', e)
    }
  }, [currentSessionId])

  // Update current session messages when messages change
  useEffect(() => {
    if (currentSessionId && messages.length > 0) {
      setChatSessions(prev => prev.map(session => 
        session.id === currentSessionId 
          ? { ...session, messages, updatedAt: new Date().toISOString() }
          : session
      ))
    }
  }, [messages, currentSessionId])

  // Helper: Create new chat session
  const createNewSession = () => {
    const newSession = {
      id: Date.now().toString(),
      title: 'New Chat',
      messages: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }
    setChatSessions(prev => [newSession, ...prev])
    setCurrentSessionId(newSession.id)
    setMessages([])
    setInputText('')
    setUploadedFile(null)
  }

  // Helper: Load a chat session
  const loadSession = (sessionId) => {
    const session = chatSessions.find(s => s.id === sessionId)
    if (session) {
      setCurrentSessionId(sessionId)
      setMessages(session.messages)
      setInputText('')
      setUploadedFile(null)
    }
  }

  // Helper: Delete a chat session
  const deleteSession = (sessionId, e) => {
    e.stopPropagation() // Prevent triggering loadSession
    
    // Remove session from list
    setChatSessions(prev => prev.filter(s => s.id !== sessionId))
    
    // If deleting current session, switch to another or create new
    if (sessionId === currentSessionId) {
      const remainingSessions = chatSessions.filter(s => s.id !== sessionId)
      if (remainingSessions.length > 0) {
        // Load the most recent session
        loadSession(remainingSessions[0].id)
      } else {
        // No sessions left, create new one
        setCurrentSessionId(null)
        setMessages([])
        setInputText('')
        setUploadedFile(null)
      }
    }
  }

  // Helper: Update session title based on first message
  const updateSessionTitle = (sessionId, firstMessage) => {
    setChatSessions(prev => prev.map(session =>
      session.id === sessionId
        ? { ...session, title: firstMessage.substring(0, 40) + '...' }
        : session
    ))
  }

  const handleFileUpload = (e) => {
    const file = e.target.files[0]
    if (file) {
      setUploadedFile(file)
    }
  }

  const removeFile = () => {
    setUploadedFile(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const handleSend = async () => {
    if (!inputText.trim() && !uploadedFile) return

    // Create new session if none exists
    if (!currentSessionId) {
      createNewSession()
      // Wait a bit for state to update
      await new Promise(resolve => setTimeout(resolve, 100))
    }

    // Update session title with first message
    if (messages.length === 0 && inputText) {
      updateSessionTitle(currentSessionId, inputText)
    }

    const userMessage = {
      role: 'user',
      content: inputText,
      file: uploadedFile ? uploadedFile.name : null,
      timestamp: new Date()
    }

    setMessages(prev => [...prev, userMessage])
    setIsLoading(true)

    try {
      let response

      if (uploadedFile) {
        // Upload file và phân tích
        const formData = new FormData()
        formData.append('file', uploadedFile)
        formData.append('query', inputText || 'Phân tích file này')
        formData.append('send_telegram', sendTelegram)

        response = await axios.post('/api/analyze-file', formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        })
      } else {
        // Gửi query text - Dùng endpoint có sẵn của backend
        response = await axios.post('/api/smart-analyze', {
          query: inputText,
          send_telegram: sendTelegram
        })
      }

      const assistantMessage = {
        role: 'assistant',
        content: response.data,
        timestamp: new Date()
      }

      setMessages(prev => [...prev, assistantMessage])
      setChatHistory(prev => [...prev, { query: inputText, response: response.data }])
    } catch (error) {
      console.error('Error:', error)
      const errorMessage = {
        role: 'assistant',
        content: {
          error: true,
          message: error.response?.data?.detail || 'Đã xảy ra lỗi khi xử lý yêu cầu'
        },
        timestamp: new Date()
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
      setInputText('')
      setUploadedFile(null)
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
    }
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleRealtimeAnalysis = async () => {
    if (isLoading) return

    const realtimeMessage = {
      role: 'user',
      content: '⚡ Chạy phân tích realtime (5 phút trước)',
      timestamp: new Date()
    }

    setMessages(prev => [...prev, realtimeMessage])
    setIsLoading(true)

    try {
      // Gọi API với query đặc biệt cho realtime
      const response = await axios.post('/api/smart-analyze', {
        query: '5 phút trước có tấn công không?',
        send_telegram: true,
        source_label: 'realtime'
      })

      const assistantMessage = {
        role: 'assistant',
        content: response.data,
        timestamp: new Date()
      }

      setMessages(prev => [...prev, assistantMessage])
      setChatHistory(prev => [...prev, { 
        query: '⚡ Realtime Analysis', 
        response: response.data 
      }])
    } catch (error) {
      console.error('Error:', error)
      const errorMessage = {
        role: 'assistant',
        content: {
          error: true,
          message: error.response?.data?.detail || 'Lỗi khi chạy realtime analysis'
        },
        timestamp: new Date()
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="app">
      <div className="sidebar">
        <div className="sidebar-header">
          <h2>Security Analysis</h2>
          <button 
            className="new-chat-btn"
            onClick={createNewSession}
            title="Tạo chat mới"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path d="M12 5v14M5 12h14" strokeWidth="2" strokeLinecap="round"/>
            </svg>
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="nav-tabs">
          <button 
            className={`nav-tab ${activeView === 'chat' ? 'active' : ''}`}
            onClick={() => setActiveView('chat')}
          >
            <MessageSquare size={20} />
            <span>Chat</span>
          </button>
          <button 
            className={`nav-tab ${activeView === 'statistics' ? 'active' : ''}`}
            onClick={() => setActiveView('statistics')}
          >
            <BarChart3 size={20} />
            <span>Thống Kê</span>
          </button>
          <button 
            className={`nav-tab ${activeView === 'monitoring' ? 'active' : ''}`}
            onClick={() => setActiveView('monitoring')}
          >
            <Clock size={20} />
            <span>Giám Sát</span>
          </button>
        </div>
        
        <div className="chat-list">
          <div className="chat-section">
            <h3>Previous chats</h3>
            {chatSessions.map((session) => (
              <div 
                key={session.id} 
                className={`chat-item ${session.id === currentSessionId ? 'active' : ''}`}
                onClick={() => loadSession(session.id)}
              >
                <FileText size={16} />
                <span className="chat-item-title">{session.title}</span>
                <button 
                  className="delete-chat-btn"
                  onClick={(e) => deleteSession(session.id, e)}
                  title="Xóa chat"
                >
                  <X size={14} />
                </button>
              </div>
            ))}
            {chatSessions.length === 0 && (
              <div className="chat-item" style={{ opacity: 0.5, cursor: 'default' }}>
                <span>Chưa có chat nào</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="main-content">
        {activeView === 'monitoring' ? (
          <CronMonitoring />
        ) : activeView === 'statistics' ? (
          <Statistics />
        ) : (
          <div className="chat-container">
        <div className="chat-header">
          <div className="header-info">
            <h1>Security Analysis Chat</h1>
            <div className="header-actions">
              <div className="dropdown-wrapper">
                <button 
                  className="icon-btn menu-btn" 
                  onClick={() => setShowMenu(!showMenu)}
                  title="Menu"
                >
                  ⋯
                </button>
                {showMenu && (
                  <div className="dropdown-menu">
                    <button onClick={() => { 
                      if (confirm('Bạn có chắc muốn xóa toàn bộ lịch sử chat?')) {
                        setChatHistory([]);
                        setMessages([]);
                        // Clear localStorage as well
                        localStorage.removeItem('chatMessages');
                        localStorage.removeItem('chatHistory');
                        alert('✅ Đã xóa lịch sử chat');
                      }
                      setShowMenu(false);
                    }}>
                      🗑️ Xóa lịch sử
                    </button>
                    <button onClick={() => { 
                      const dataStr = JSON.stringify(messages, null, 2);
                      const dataBlob = new Blob([dataStr], {type: 'application/json'});
                      const url = URL.createObjectURL(dataBlob);
                      const link = document.createElement('a');
                      link.href = url;
                      link.download = `chat_history_${new Date().toISOString()}.json`;
                      link.click();
                      setShowMenu(false);
                      alert('✅ Đã export chat history');
                    }}>
                      📥 Export chat
                    </button>
                    <button onClick={() => { 
                      setShowMenu(false);
                      setShowSettings(true);
                    }}>
                      ⚙️ Cài đặt
                    </button>
                  </div>
                )}
              </div>
              
              <div className="dropdown-wrapper">
                <button 
                  className="icon-btn settings-btn" 
                  onClick={() => setShowSettings(!showSettings)}
                  title="Cài đặt"
                >
                  ⚙
                </button>
                {showSettings && (
                  <div className="dropdown-menu">
                    <button onClick={() => { 
                      alert('🔑 API Keys:\n\n' +
                            'Groq API: Configured ✓\n' +
                            'Google AI: Configured ✓\n' +
                            'AbuseIPDB: Configured ✓\n\n' +
                            'Để thay đổi, chỉnh sửa file .env');
                      setShowSettings(false);
                    }}>
                      🔑 API Keys
                    </button>
                    <button onClick={() => { 
                      alert('🤖 Models đang sử dụng:\n\n' +
                            'Analyze: openai/gpt-oss-120b\n' +
                            'TI Agent: llama-3.1-8b-instant\n' +
                            'Recommend: gemini-2.0-flash-lite\n' +
                            'Report: gemini-2.5-flash-lite\n\n' +
                            'Để thay đổi, chỉnh sửa file .env');
                      setShowSettings(false);
                    }}>
                      🤖 Chọn Model
                    </button>
                    <button onClick={() => { 
                      alert('📱 Telegram Configuration:\n\n' +
                            'Bot Token: Configured ✓\n' +
                            'Chat ID: Configured ✓\n\n' +
                            'Để thay đổi, chỉnh sửa file .env:\n' +
                            'TELEGRAM_BOT_TOKEN=...\n' +
                            'TELEGRAM_CHAT_ID=...');
                      setShowSettings(false);
                    }}>
                      📱 Cấu hình Telegram
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="messages-container">
          {messages.length === 0 && (
            <div className="welcome-message">
              <h2>Chào mừng đến với Security Analysis Chat</h2>
              <p>Upload file log hoặc đặt câu hỏi về bảo mật</p>
            </div>
          )}

          {messages.map((msg, idx) => (
            <div key={idx} className={`message ${msg.role}`}>
              {msg.role === 'assistant' && (
                <div className="message-avatar">
                  <div className="avatar-icon">🤖</div>
                </div>
              )}
              
              <div className="message-content">
                {msg.file && (
                  <div className="file-attachment">
                    <FileText size={16} />
                    <span>{msg.file}</span>
                  </div>
                )}
                
                {msg.content.error ? (
                  <div className="error-message">
                    ❌ {msg.content.message}
                  </div>
                ) : msg.role === 'assistant' ? (
                  <AssistantResponse data={msg.content} />
                ) : (
                  <p>{msg.content}</p>
                )}
              </div>
            </div>
          ))}

          {isLoading && (
            <div className="message assistant">
              <div className="message-avatar">
                <div className="avatar-icon">🤖</div>
              </div>
              <div className="message-content">
                <div className="loading-indicator">
                  <Loader2 className="spinner" size={20} />
                  <span>Đang phân tích...</span>
                </div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        <div className="input-container">
          {uploadedFile && (
            <div className="file-preview">
              <FileText size={16} />
              <span>{uploadedFile.name}</span>
              <button onClick={removeFile} className="remove-file-btn">
                <X size={16} />
              </button>
            </div>
          )}

          <div className="input-wrapper">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".log,.txt,.csv,.pdf,application/pdf"
              style={{ display: 'none' }}
            />
            
            <button 
              className="attach-btn"
              onClick={() => fileInputRef.current?.click()}
            >
              <Paperclip size={20} />
            </button>

            <textarea
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Nhập câu hỏi hoặc upload file..."
              rows={1}
            />

            <label className="telegram-checkbox">
              <input
                type="checkbox"
                checked={sendTelegram}
                onChange={(e) => setSendTelegram(e.target.checked)}
              />
              <span>📱 Gửi Telegram</span>
            </label>

            <button 
              className="send-btn"
              onClick={handleSend}
              disabled={isLoading || (!inputText.trim() && !uploadedFile)}
            >
              <Send size={20} />
            </button>
          </div>
        </div>
        </div>
        )}
      </div>
    </div>
  )
}

function AssistantResponse({ data }) {
  if (!data) return null

  return (
    <div className="assistant-response">
      {/* Workflow Path */}
      {data.workflow_path && data.workflow_path.length > 0 && (
        <div className="workflow-display">
          <div className="workflow-label">🔄 Workflow:</div>
          <div className="workflow-nodes">
            {data.workflow_path.map((node, idx) => (
              <React.Fragment key={idx}>
                <span className="workflow-node">{node}</span>
                {idx < data.workflow_path.length - 1 && (
                  <span className="workflow-arrow">→</span>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {/* Supervisor Reasoning */}
      {data.supervisor_reasoning && (
        <div className="supervisor-reasoning">
          <strong>🤔 Phân tích:</strong> {data.supervisor_reasoning}
        </div>
      )}

      {/* Findings Summary */}
      {data.findings_summary && (
        <div className="findings-card">
          <h3>## Key Findings</h3>
          <div className="findings-content">
            <p><strong>Tổng số sự kiện:</strong> {data.findings_summary.total_events}</p>
            <p><strong>Sự kiện tấn công:</strong> {data.findings_summary.total_attack_events}</p>
            <p><strong>Mức độ nghiêm trọng:</strong> 
              <span className={`severity ${data.findings_summary.severity_level}`}>
                {data.findings_summary.severity_level}
              </span>
            </p>
            
            {data.findings_summary.attack_breakdown && (
              <div className="attack-breakdown">
                <h4>Phân loại tấn công:</h4>
                {data.findings_summary.attack_breakdown.map((attack, idx) => (
                  <div key={idx} className="attack-item">
                    <span className="attack-type">{attack.attack_type}</span>
                    <span className="attack-count">{attack.count} ({attack.percentage}%)</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* CSV Data Table */}
      {data.csv_data && (
        <DataTable 
          data={data.csv_data} 
          filename={data.csv_filename || 'summary.csv'} 
        />
      )}

      {/* Attack Events CSV */}
      {data.attack_events_ref && (
        <div className="file-export">
          <FileText size={20} />
          <div>
            <p><strong>Attack Events CSV</strong></p>
            <p className="file-path">{data.attack_events_ref.csv_path}</p>
          </div>
          <a 
            href={`/api/download?file=${encodeURIComponent(data.attack_events_ref.csv_path)}`}
            className="download-btn"
            download
          >
            <Download size={16} />
            Download CSV
          </a>
        </div>
      )}

      {/* PDF Report */}
      {data.pdf_path && (
        <div className="file-export pdf-export">
          <FileText size={20} color="#dc3545" />
          <div>
            <p><strong>📄 PDF Report</strong></p>
            <p className="file-path">{data.pdf_path}</p>
          </div>
          <a 
            href={`/api/download?file=${encodeURIComponent(data.pdf_path)}`}
            className="download-btn pdf-btn"
            download
          >
            <Download size={16} />
            Download PDF
          </a>
        </div>
      )}

      {/* GenRule Summary - Priority for generic_rule job */}
      {data.job_type === 'generic_rule' && data.genrule_summary && (
        <div className="genrule-section">
          <h3>🛡️ Detection Rules Generated</h3>
          
          <div className="rule-block">
            <h4>📋 Sigma Rule (YAML)</h4>
            <pre className="code-block">{data.genrule_summary.sigma_rule}</pre>
          </div>
          
          <div className="rule-block">
            <h4>🔍 Splunk SPL Query</h4>
            <pre className="code-block">{data.genrule_summary.splunk_spl}</pre>
          </div>
          
          {data.genrule_summary.notes && (
            <div className="rule-block">
              <h4>📝 Hướng Dẫn Triển Khai</h4>
              <div dangerouslySetInnerHTML={{ __html: formatMarkdown(data.genrule_summary.notes) }} />
            </div>
          )}
          
          {/* RAG Sources for GenRule */}
          {data.rag_sources && data.rag_sources.length > 0 && (
            <div className="rule-block">
              <RAGSources sources={data.rag_sources} />
            </div>
          )}
        </div>
      )}

      {/* TI Summary - Show for ip_reputation or log_analysis with TI */}
      {data.ti_summary && (
        <div className="ti-summary-card">
          <h3>🔍 Threat Intelligence Analysis</h3>
          
          {data.ti_summary.iocs && data.ti_summary.iocs.length > 0 && (
            <div className="iocs-list">
              <h4>📊 IP Reputation Results:</h4>
              {data.ti_summary.iocs.map((ioc, idx) => (
                <div key={idx} className={`ioc-item risk-${ioc.risk || 'unknown'}`}>
                  <div className="ioc-header">
                    <span className="ioc-ip">🌐 {ioc.ip}</span>
                    <div className="ioc-badges">
                      <span className={`risk-badge ${ioc.risk || 'unknown'}`}>
                        {ioc.risk === 'high' ? '🔴 High Risk' : 
                         ioc.risk === 'medium' ? '🟡 Medium Risk' : 
                         ioc.risk === 'low' ? '🟢 Low Risk' : 
                         '⚪ Unknown'}
                      </span>
                      {ioc.is_internal && (
                        <span className="asset-badge internal">🏢 Internal</span>
                      )}
                      {ioc.is_protected && (
                        <span className="asset-badge protected">🛡️ Protected</span>
                      )}
                      {ioc.is_authorized_attacker && (
                        <span className="asset-badge authorized">🎯 Authorized</span>
                      )}
                    </div>
                  </div>
                  
                  {/* Asset Info Section */}
                  {ioc.asset_info && (
                    <div className="asset-info-section">
                      <h5>🏢 Internal Asset Information:</h5>
                      <div className="asset-details">
                        <p><strong>Hostname:</strong> {ioc.asset_info.hostname}</p>
                        <p><strong>Type:</strong> {ioc.asset_info.asset_type}</p>
                        <p><strong>Label:</strong> {ioc.asset_info.label}</p>
                        {ioc.asset_info.description && (
                          <p><strong>Description:</strong> {ioc.asset_info.description}</p>
                        )}
                        {ioc.asset_info.owner && (
                          <p><strong>Owner:</strong> {ioc.asset_info.owner}</p>
                        )}
                        {ioc.asset_info.location && (
                          <p><strong>Location:</strong> {ioc.asset_info.location}</p>
                        )}
                      </div>
                    </div>
                  )}
                  
                  {/* Threat Intelligence Section */}
                  <div className="ti-info-section">
                    <h5>🔍 Threat Intelligence:</h5>
                    <div className="ioc-details">
                      <p><strong>Abuse Score:</strong> {ioc.abuse_score !== null ? `${ioc.abuse_score}/100` : 'N/A'}</p>
                      {ioc.country && <p><strong>Country:</strong> {ioc.country}</p>}
                      {ioc.usage_type && <p><strong>Usage Type:</strong> {ioc.usage_type}</p>}
                      {ioc.isp && <p><strong>ISP:</strong> {ioc.isp}</p>}
                    </div>
                  </div>
                  
                  {/* Additional Notes */}
                  {ioc.notes && ioc.notes.trim() && (
                    <div className="notes-section">
                      <p><strong>📝 Additional Notes:</strong></p>
                      <p className="notes-text">{ioc.notes}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          
          {data.ti_summary.ti_overall && (
            <div className="ti-overall">
              <h4>📋 Overall Assessment:</h4>
              <p><strong>Max Risk:</strong> <span className={`risk-badge ${data.ti_summary.ti_overall.max_risk}`}>
                {data.ti_summary.ti_overall.max_risk}
              </span></p>
              {data.ti_summary.ti_overall.notes && (
                <p><strong>Notes:</strong> {data.ti_summary.ti_overall.notes}</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* RAG Answer - Show only if NOT generic_rule */}
      {data.job_type !== 'generic_rule' && data.rag_answer && (
        <div className="rag-answer">
          <div dangerouslySetInnerHTML={{ 
            __html: formatMarkdown(
              typeof data.rag_answer === 'object' && data.rag_answer.answer
                ? data.rag_answer.answer
                : data.rag_answer
            ) 
          }} />
        </div>
      )}

      {/* RAG Sources - Check both rag_answer.sources and root rag_sources */}
      {((data.rag_answer && typeof data.rag_answer === 'object' && data.rag_answer.sources) || 
        (data.rag_sources && data.rag_sources.length > 0)) && (
        <RAGSources sources={
          (data.rag_answer && typeof data.rag_answer === 'object' && data.rag_answer.sources) || 
          data.rag_sources
        } />
      )}

      {/* Report Markdown */}
      {data.report_markdown && (
        <div className="report-section">
          <h3>📄 Báo cáo chi tiết</h3>
          <div dangerouslySetInnerHTML={{ __html: formatMarkdown(data.report_markdown) }} />
        </div>
      )}

      {/* Asset Summary */}
      {data.asset_summary && (
        <div className="asset-summary">
          <h3>🖥️ Thông tin Asset</h3>
          {data.asset_summary.answer && (
            <div className="asset-answer">
              <p style={{ whiteSpace: 'pre-wrap' }}>{data.asset_summary.answer}</p>
            </div>
          )}
          {data.asset_summary.sources && data.asset_summary.sources.length > 0 && (
            <div className="asset-sources">
              <h4>📚 Nguồn tham khảo:</h4>
              <ul>
                {data.asset_summary.sources.map((source, idx) => (
                  <li key={idx}>
                    {source.file} (Category: {source.category}, Score: {source.score.toFixed(2)})
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function formatMarkdown(text) {
  if (!text) return ''
  return text
    .replace(/### (.*)/g, '<h3>$1</h3>')
    .replace(/## (.*)/g, '<h2>$1</h2>')
    .replace(/# (.*)/g, '<h1>$1</h1>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br/>')
}

export default App
