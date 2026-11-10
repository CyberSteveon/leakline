import { useState, useEffect, useRef } from 'react'
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
  FileSearch,
  StopCircle,
} from 'lucide-react'
import { describeOutcome, waitForResult } from './scanOutcome.js'
import './App.css'

function App() {
  const [dependencies, setDependencies] = useState({
    gitleaks_installed: false,
    semgrep_installed: false,
  })
  const [installing, setInstalling] = useState(false)
  const [uninstalling, setUninstalling] = useState(null)
  const [targetPath, setTargetPath] = useState('')
  const [scanState, setScanState] = useState('idle')
  const [progress, setProgress] = useState(null)
  const [result, setResult] = useState(null)
  const [scanError, setScanError] = useState('')
  const activeSession = useRef(null)
  const findings = result?.findings ?? []
  const scanSummary = result?.summary
  const busy = ['starting', 'running', 'cancelling'].includes(scanState)

  useEffect(() => {
    refreshDependencies()
    return () => {
      activeSession.current = null
    }
  }, [])

  const refreshDependencies = async () => {
    try {
      const status = await invoke('get_dependency_status')
      setDependencies(status)
    } catch (error) {
      console.error('Failed to get dependency status:', error)
    }
  }

  const installDependencies = async () => {
    setInstalling(true)
    try {
      await invoke('install_dependency')
      await refreshDependencies()
    } catch (error) {
      console.error('Failed to install dependencies:', error)
      alert('Failed to install dependencies: ' + error)
    } finally {
      setInstalling(false)
    }
  }

  const uninstallDependency = async (depId) => {
    setUninstalling(depId)
    try {
      await invoke('uninstall_dependency', { depId })
      await refreshDependencies()
    } catch (error) {
      console.error('Failed to uninstall dependency:', error)
      alert('Failed to uninstall dependency: ' + error)
    } finally {
      setUninstalling(null)
    }
  }

  const startScan = async () => {
    if (!targetPath || activeSession.current) {
      return
    }
    const scanSession = { id: null }
    activeSession.current = scanSession
    const isCurrentSession = () => activeSession.current === scanSession
    setScanState('starting')
    setProgress(null)
    setResult(null)
    setScanError('')
    let unlisten
    try {
      unlisten = await listen('scan-progress', ({ payload }) => {
        if (isCurrentSession() && payload.scanId === scanSession.id) {
          setProgress(payload)
        }
      })
      if (!isCurrentSession()) {
        return
      }
      const started = await invoke('start_scan', { request: { targetPath } })
      scanSession.id = started.scanId
      if (!isCurrentSession()) {
        return
      }
      setScanState('running')
      const report = await waitForResult(
        scanSession.id,
        (scanId) => invoke('get_scan_result', { scanId }),
        () => new Promise((resolve) => setTimeout(resolve, 400)),
        isCurrentSession,
      )
      if (!isCurrentSession()) {
        return
      }
      setResult(report)
      setScanState('completed')
      // React now owns the displayed report; release the backend copy.
      await invoke('dismiss_scan_result', { scanId: scanSession.id }).catch(
        () => {},
      )
    } catch (error) {
      if (isCurrentSession()) {
        setScanError(
          scanSession.id == null
            ? error?.message || 'Could not start scan.'
            : 'Scan result unavailable. No conclusion is available.',
        )
        setScanState('error')
      }
    } finally {
      unlisten?.()
      if (isCurrentSession()) {
        activeSession.current = null
      }
    }
  }

  const cancelScan = async () => {
    const scanSession = activeSession.current
    if (!scanSession?.id) {
      return
    }
    setScanState('cancelling')
    try {
      await invoke('cancel_scan', { scanId: scanSession.id })
    } catch (error) {
      // Completion may already have won the race. Continue waiting for its result.
      if (
        activeSession.current === scanSession &&
        error?.code !== 'scan_not_active'
      ) {
        setScanError(
          'Cancellation was not acknowledged. Waiting for the scan result.',
        )
      }
    }
  }

  const dependenciesReady =
    dependencies.gitleaks_installed && dependencies.semgrep_installed

  const handleBrowse = async () => {
    try {
      const selectedPath = await open({
        directory: true,
        multiple: false,
      })
      if (selectedPath) {
        setTargetPath(selectedPath)
      }
    } catch (error) {
      console.error('Failed to open dialog:', error)
    }
  }

  return (
    <div className="container">
      <div className="panel">
        <div className="panel-header">
          <h2>
            <Settings size={20} /> Dependencies
          </h2>
        </div>

        <div className="dependency-status">
          <p
            style={{
              fontSize: '0.85rem',
              color: 'var(--text-secondary)',
              marginBottom: '1rem',
            }}
          >
            Dependencies are needed for advanced secrets detection (Gitleaks)
            and static analysis (Semgrep). The native scanner will function
            without them.
          </p>
          <div className="status-info">
            <div
              className={`status-indicator ${dependencies.gitleaks_installed ? 'installed' : 'missing'}`}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
              >
                {dependencies.gitleaks_installed ? (
                  <CheckCircle size={16} />
                ) : (
                  <XCircle size={16} />
                )}
                <span>
                  Gitleaks{' '}
                  {dependencies.gitleaks_installed ? 'Installed' : 'Missing'}
                </span>
              </div>
              {dependencies.gitleaks_installed && (
                <button
                  className="button"
                  style={{
                    padding: '0.2rem 0.5rem',
                    fontSize: '0.75rem',
                    borderColor: 'var(--accent-red)',
                    color: 'var(--accent-red)',
                    background: 'transparent',
                  }}
                  onClick={() => uninstallDependency('gitleaks')}
                  disabled={uninstalling === 'gitleaks'}
                >
                  {uninstalling === 'gitleaks'
                    ? 'Uninstalling...'
                    : 'Uninstall'}
                </button>
              )}
            </div>
            <div
              className={`status-indicator ${dependencies.semgrep_installed ? 'installed' : 'missing'}`}
              style={{
                marginTop: '0.5rem',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
              >
                {dependencies.semgrep_installed ? (
                  <CheckCircle size={16} />
                ) : (
                  <XCircle size={16} />
                )}
                <span>
                  Semgrep{' '}
                  {dependencies.semgrep_installed ? 'Installed' : 'Missing'}
                </span>
              </div>
              {dependencies.semgrep_installed && (
                <button
                  className="button"
                  style={{
                    padding: '0.2rem 0.5rem',
                    fontSize: '0.75rem',
                    borderColor: 'var(--accent-red)',
                    color: 'var(--accent-red)',
                    background: 'transparent',
                  }}
                  onClick={() => uninstallDependency('semgrep')}
                  disabled={uninstalling === 'semgrep'}
                >
                  {uninstalling === 'semgrep' ? 'Uninstalling...' : 'Uninstall'}
                </button>
              )}
            </div>
          </div>

          <button
            className="button"
            onClick={installDependencies}
            disabled={installing || dependenciesReady}
          >
            <Download size={16} />
            {installing
              ? 'Installing...'
              : dependenciesReady
                ? 'Up to Date'
                : 'Install Missing'}
          </button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h2>
            <Shield size={20} /> Security Scan
          </h2>
        </div>

        <div className="input-group">
          <label>Local repository directory</label>
          <div style={{ display: 'flex', gap: '1rem' }}>
            <input
              style={{ flex: 1 }}
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="/path/to/your/project"
              disabled={busy}
            />
            <button className="button" onClick={handleBrowse} disabled={busy}>
              Browse
            </button>
            {busy ? (
              <button
                className="button danger"
                onClick={cancelScan}
                disabled={scanState !== 'running'}
              >
                <StopCircle size={16} />{' '}
                {scanState === 'cancelling'
                  ? 'Cancellation requested…'
                  : scanState === 'starting'
                    ? 'Starting…'
                    : 'Stop Scan'}
              </button>
            ) : (
              <button
                className="button"
                onClick={startScan}
                disabled={!targetPath}
              >
                <Play size={16} /> Start Scan
              </button>
            )}
          </div>
        </div>

        {scanError && <p role="alert">{scanError}</p>}
        {busy && progress && (
          <div className="progress-container">
            <div className="progress-header">
              <span>Scanning... ({progress.phase})</span>
              <span>
                {progress.processedFiles || 0} / {progress.selectedFiles || '?'}{' '}
                files
              </span>
            </div>
            <div className="progress-bar-bg">
              <div
                className="progress-bar-fill"
                style={{
                  width: `${progress.selectedFiles ? Math.min(100, Math.round((progress.processedFiles / progress.selectedFiles) * 100)) : 0}%`,
                }}
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

      {result && (
        <div className="panel">
          <div className="panel-header">
            <h2>
              <FileSearch size={20} /> Findings
            </h2>
          </div>

          <p role="status">
            <strong>{describeOutcome(result)}</strong>
          </p>
          <p>Target: {result.target.displayPath}</p>
          <p>
            Native coverage: {result.coverage.nativeProcessedFiles} of{' '}
            {result.coverage.selectedFiles} selected files checked.{' '}
            {result.coverage.skippedByPolicy} outside the file policy;{' '}
            {result.coverage.excludedVcsEntries} VCS entries excluded;{' '}
            {result.coverage.skippedSymlinks} symlinks and{' '}
            {result.coverage.skippedOversized} oversized files skipped.
          </p>
          <ul>
            {['native', 'gitleaks', 'semgrep'].map((id) => {
              const run = result.scannerRuns.find((run) => run.scannerId === id)
              return (
                <li key={id}>
                  {id}: {run ? run.status.replaceAll('_', ' ') : 'not run'}
                </li>
              )
            })}
          </ul>
          {result.issues.length > 0 && (
            <details>
              <summary>{result.issues.length} scan issues</summary>
              <ul>
                {result.issues.map((issue, i) => (
                  <li key={i}>
                    {issue.stage}: {issue.message} {issue.relativePath}
                  </li>
                ))}
              </ul>
            </details>
          )}
          <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
            <div className="stat-box">
              <div className="value">{scanSummary?.findingCount || 0}</div>
              <div className="label">Total Findings</div>
            </div>
            <div className="stat-box">
              <div className="value" style={{ color: 'var(--accent-red)' }}>
                {(scanSummary?.criticalCount || 0) +
                  (scanSummary?.highCount || 0)}
              </div>
              <div className="label">Critical & High</div>
            </div>
            <div className="stat-box">
              <div className="value">{scanSummary?.mediumCount || 0}</div>
              <div className="label">Medium</div>
            </div>
          </div>

          {findings.length > 0 && (
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
                  {findings.map((finding, index) => (
                    <tr key={index}>
                      <td>
                        <span
                          className={`severity-badge severity-${finding.severity}`}
                        >
                          {finding.severity}
                        </span>
                      </td>
                      <td>
                        <span className="code-block">
                          {finding.location?.relativePath}
                        </span>
                        {finding.location?.startLine && (
                          <span
                            style={{
                              marginLeft: 5,
                              fontSize: '0.8rem',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            :{finding.location.startLine}
                          </span>
                        )}
                      </td>
                      <td>
                        <strong>{finding.ruleId}</strong>
                        <div
                          style={{
                            fontSize: '0.75rem',
                            color: 'var(--text-secondary)',
                            marginTop: '0.25rem',
                          }}
                        >
                          {finding.title}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default App
