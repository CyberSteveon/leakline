import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { open } from '@tauri-apps/plugin-dialog'
import { 
  Shield, 
  Settings, 
  Play, 
  Download, 
  CheckCircle, 
  XCircle,
  AlertTriangle,
  FileSearch,
  StopCircle
} from 'lucide-react'
import './App.css'

function App() {
  const [deps, setDeps] = useState({ gitleaks_installed: false, semgrep_installed: false })
  const [installing, setInstalling] = useState(false)
  const [targetPath, setTargetPath] = useState('')
  const [scanState, setScanState] = useState('idle') // idle, running, completed, error
  const [progress, setProgress] = useState(null)
  const [findings, setFindings] = useState([])
  const [scanSummary, setScanSummary] = useState(null)

  useEffect(() => {
    checkDeps()

    let unlistenProgress
    let unlistenComplete

    const setupListeners = async () => {
      unlistenProgress = await listen('scan-progress', (event) => {
        setProgress(event.payload)
      })

      unlistenComplete = await listen('scan-complete', (event) => {
        const payload = event.payload
        setScanState('completed')
        setScanSummary(payload.summary)
        
        // Fetch findings
        invoke('get_scan_result', { scanId: payload.scanId })
          .then(result => {
            setFindings(result.findings || [])
          })
          .catch(console.error)
      })
    }

    setupListeners()

    return () => {
      if (unlistenProgress) unlistenProgress()
      if (unlistenComplete) unlistenComplete()
    }
  }, [])

  const checkDeps = async () => {
    try {
      const status = await invoke('get_dependency_status')
      setDeps(status)
    } catch (e) {
      console.error("Failed to get dependency status:", e)
    }
  }

  const installDeps = async () => {
    setInstalling(true)
    try {
      await invoke('install_dependency')
      await checkDeps()
    } catch (e) {
      console.error("Failed to install dependencies:", e)
      alert("Failed to install dependencies: " + e)
    } finally {
      setInstalling(false)
    }
  }

  const startScan = async () => {
    if (!targetPath) return
    
    setScanState('running')
    setProgress(null)
    setFindings([])
    setScanSummary(null)
    
    try {
      await invoke('start_scan', {
        request: {
          targetPath,
          scannerIds: null,
          excludePaths: null,
          includePaths: null
        }
      })
    } catch (e) {
      console.error("Failed to start scan:", e)
      setScanState('error')
      alert("Error starting scan: " + (e.message || e))
    }
  }

  const cancelScan = async () => {
    if (!progress?.scanId) return
    try {
      await invoke('cancel_scan', { scanId: progress.scanId })
      setScanState('idle')
    } catch (e) {
      console.error("Failed to cancel scan:", e)
    }
  }

  const depsReady = deps.gitleaks_installed && deps.semgrep_installed

  const handleBrowse = async () => {
    try {
      const selectedPath = await open({
        directory: true,
        multiple: false,
      })
      if (selectedPath) {
        setTargetPath(selectedPath)
      }
    } catch (e) {
      console.error("Failed to open dialog:", e)
    }
  }

  return (
    <div className="container">
      <div className="panel">
        <div className="panel-header">
          <h2><Settings size={20} /> Dependencies</h2>
        </div>
        
        <div className="dependency-status">
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
            Dependencies are needed for advanced secrets detection (Gitleaks) and static analysis (Semgrep). The native scanner will function without them.
          </p>
          <div className="status-info">
            <div className={`status-indicator ${deps.gitleaks_installed ? 'installed' : 'missing'}`}>
              {deps.gitleaks_installed ? <CheckCircle size={16} /> : <XCircle size={16} />}
              <span>Gitleaks {deps.gitleaks_installed ? 'Installed' : 'Missing'}</span>
            </div>
            <div className={`status-indicator ${deps.semgrep_installed ? 'installed' : 'missing'}`} style={{ marginTop: '0.5rem' }}>
              {deps.semgrep_installed ? <CheckCircle size={16} /> : <XCircle size={16} />}
              <span>Semgrep {deps.semgrep_installed ? 'Installed' : 'Missing'}</span>
            </div>
          </div>
          
          <button 
            className="button" 
            onClick={installDeps} 
            disabled={installing || depsReady}
          >
            <Download size={16} />
            {installing ? 'Installing...' : depsReady ? 'Up to Date' : 'Install Missing'}
          </button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h2><Shield size={20} /> Security Scan</h2>
        </div>
        
        <div className="input-group">
          <label>Target Path (Directory or File)</label>
          <div style={{ display: 'flex', gap: '1rem' }}>
            <input 
              style={{ flex: 1 }}
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="/path/to/your/project"
              disabled={scanState === 'running'}
            />
            <button 
              className="button" 
              onClick={handleBrowse} 
              disabled={scanState === 'running'}
            >
              Browse
            </button>
            {scanState === 'running' ? (
              <button className="button danger" onClick={cancelScan}>
                <StopCircle size={16} /> Stop Scan
              </button>
            ) : (
              <button 
                className="button" 
                onClick={startScan} 
                disabled={!targetPath || !depsReady}
              >
                <Play size={16} /> Start Scan
              </button>
            )}
          </div>
        </div>

        {scanState === 'running' && progress && (
          <div className="progress-container">
            <div className="progress-header">
              <span>Scanning... ({progress.phase})</span>
              <span>{progress.processedFiles || 0} / {progress.selectedFiles || '?'} files</span>
            </div>
            <div className="progress-bar-bg">
              <div 
                className="progress-bar-fill" 
                style={{ width: `${progress.selectedFiles ? Math.min(100, Math.round((progress.processedFiles / progress.selectedFiles) * 100)) : 0}%` }}
              ></div>
            </div>
            <div className="stats-grid">
              <div className="stat-box">
                <div className="value">{progress.findingCount || 0}</div>
                <div className="label">Findings</div>
              </div>
              <div className="stat-box">
                <div className="value">{progress.issueCount || 0}</div>
                <div className="label">Issues</div>
              </div>
            </div>
          </div>
        )}
      </div>

      {scanState === 'completed' && (
        <div className="panel">
          <div className="panel-header">
            <h2><FileSearch size={20} /> Findings</h2>
          </div>
          
          <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
            <div className="stat-box">
              <div className="value">{scanSummary?.findingCount || 0}</div>
              <div className="label">Total Findings</div>
            </div>
            <div className="stat-box">
              <div className="value" style={{ color: 'var(--accent-red)' }}>
                {(scanSummary?.criticalCount || 0) + (scanSummary?.highCount || 0)}
              </div>
              <div className="label">Critical & High</div>
            </div>
            <div className="stat-box">
              <div className="value">{scanSummary?.mediumCount || 0}</div>
              <div className="label">Medium</div>
            </div>
          </div>

          {findings.length > 0 ? (
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>File</th>
                    <th>Rule / Title</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f, i) => (
                    <tr key={i}>
                      <td>
                        <span className={`severity-badge severity-${f.severity}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td>
                        <span className="code-block">{f.location?.relativePath}</span>
                        {f.location?.startLine && <span style={{ marginLeft: 5, fontSize: '0.8rem', color: 'var(--text-secondary)' }}>:{f.location.startLine}</span>}
                      </td>
                      <td>
                        <strong>{f.ruleId}</strong>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                          {f.title}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <CheckCircle size={48} style={{ color: 'var(--success-color)' }} />
              <h3>No vulnerabilities found</h3>
              <p>Your codebase looks secure!</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default App