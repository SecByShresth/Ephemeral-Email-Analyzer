import React, { useState, useEffect, useRef } from 'react';
import { Upload, Mail, Link, Shield, AlertTriangle, CheckCircle, XCircle, Download, Trash2, Eye, EyeOff } from 'lucide-react';

// Dynamic API URL resolution for cross-environment compatibility
const getApiBaseUrl = () => {
  // Check if we're in development or production
  if (process.env.NODE_ENV === 'development') {
    // Try environment variable first
    if (process.env.REACT_APP_API_URL) {
      return process.env.REACT_APP_API_URL;
    }
    // Default to localhost for development
    return `http://${window.location.hostname}:8000`;
  }

  // For production, use the same host with port 8000
  const protocol = window.location.protocol === 'https:' ? 'https:' : 'http:';
  return `${protocol}//${window.location.hostname}:8000`;
};

const API_BASE_URL = getApiBaseUrl();

// WebSocket URL helper
const getWebSocketUrl = (analysisId) => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.hostname}:8000/ws/${analysisId}`;
};

// Animated terminal log display
const TerminalLog = ({ logs, logsEndRef }) => {
  const [logMessages, setLogMessages] = useState([]);
  const [currentTypingIndex, setCurrentTypingIndex] = useState(0);

  useEffect(() => {
    if (logs.length > logMessages.length) {
      const newLog = logs[logs.length - 1];
      const newPrompt = `> ${newLog.message}`;
      setCurrentTypingIndex(0);
      setLogMessages(prev => [...prev, { text: newPrompt, level: newLog.level, timestamp: newLog.timestamp }]);
    }
  }, [logs, logMessages]);

  useEffect(() => {
    if (currentTypingIndex < (logMessages[logMessages.length - 1]?.text.length || 0)) {
      const timer = setTimeout(() => {
        setCurrentTypingIndex(prev => prev + 1);
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [currentTypingIndex, logMessages]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logMessages, logsEndRef]);

  const getLogColor = (level) => {
    switch (level) {
      case 'INFO': return 'text-green-400';
      case 'SUCCESS': return 'text-green-300';
      case 'ERROR': return 'text-red-400';
      case 'WARN': return 'text-yellow-400';
      default: return 'text-gray-300';
    }
  };

  return (
      <div className="bg-gray-900 rounded-lg p-4 h-64 overflow-y-auto font-mono text-sm shadow-inner relative custom-scrollbar">
        <div className="flex items-center space-x-2 mb-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div className="w-3 h-3 rounded-full bg-green-500"></div>
          <span className="text-gray-400 text-xs ml-2">Analysis Log</span>
        </div>
        <div className="border-t border-gray-700 pt-2">
          {logMessages.map((log, index) => (
              <div key={index} className="flex flex-wrap items-baseline">
            <span className="text-gray-500 mr-2 min-w-[70px]">
              [{new Date(log.timestamp).toLocaleTimeString()}]
            </span>
                <span className={getLogColor(log.level)}>
              {log.text.substring(0, index === logMessages.length - 1 ? currentTypingIndex : log.text.length)}
            </span>
                {index === logMessages.length - 1 && (
                    <span className="w-2 h-4 inline-block bg-white animate-pulse-fast ml-1"></span>
                )}
              </div>
          ))}
          <div ref={logsEndRef} />
        </div>
      </div>
  );
};

function App() {
  const [activeTab, setActiveTab] = useState('headers');
  const [headers, setHeaders] = useState('');
  const [urls, setUrls] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisId, setAnalysisId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [results, setResults] = useState(null);
  const [wsConnection, setWsConnection] = useState(null);
  const [expandedSections, setExpandedSections] = useState({});

  const fileInputRef = useRef(null);
  const logsEndRef = useRef(null);

  // Scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs, logsEndRef]);

  // WebSocket
  useEffect(() => {
    if (analysisId && !wsConnection) {
      const ws = new WebSocket(getWebSocketUrl(analysisId));

      ws.onopen = () => {
        console.log('WebSocket connected');
        setWsConnection(ws);
      };

      ws.onmessage = (event) => {
        const logEntry = JSON.parse(event.data);
        setLogs(prev => [...prev, logEntry]);
      };

      ws.onclose = () => {
        console.log('WebSocket disconnected');
        setWsConnection(null);
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      return () => ws.close();
    }
  }, [analysisId, wsConnection]);

  // --- ANALYSIS HANDLERS ---
  const analyzeHeaders = async () => {
    if (!headers.trim()) {
      alert('Please paste email headers');
      return;
    }
    setIsAnalyzing(true);
    setLogs([]);
    setResults(null);

    try {
      const response = await fetch(`${API_BASE_URL}/analyze/header`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ headers }),
      });
      if (!response.ok) throw new Error(`Analysis failed: ${response.statusText}`);
      const data = await response.json();
      setAnalysisId(data.analysis_id);
      pollForResults(data.analysis_id);
    } catch (err) {
      console.error('Analysis error:', err);
      alert(`Analysis failed: ${err.message}`);
      setIsAnalyzing(false);
    }
  };

  const analyzeUrls = async () => {
    const urlList = urls.split('\n').filter(u => u.trim());
    if (urlList.length === 0) {
      alert('Please enter URLs');
      return;
    }
    setIsAnalyzing(true);
    setLogs([]);
    setResults(null);

    try {
      const response = await fetch(`${API_BASE_URL}/analyze/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls: urlList }),
      });
      if (!response.ok) throw new Error(`Analysis failed: ${response.statusText}`);
      const data = await response.json();
      setAnalysisId(data.analysis_id);
      pollForResults(data.analysis_id);
    } catch (err) {
      console.error('Analysis error:', err);
      alert(`Analysis failed: ${err.message}`);
      setIsAnalyzing(false);
    }
  };

  const analyzeFile = async () => {
    if (!selectedFile) {
      alert('Please select a file');
      return;
    }
    setIsAnalyzing(true);
    setLogs([]);
    setResults(null);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await fetch(`${API_BASE_URL}/analyze/attachment`, {
        method: 'POST',
        body: formData,
      });
      if (!response.ok) throw new Error(`Analysis failed: ${response.statusText}`);
      const data = await response.json();
      setAnalysisId(data.analysis_id);
      pollForResults(data.analysis_id);
    } catch (err) {
      console.error('Analysis error:', err);
      alert(`Analysis failed: ${err.message}`);
      setIsAnalyzing(false);
    }
  };

  // --- POLLING RESULTS ---
  const pollForResults = async (id) => {
    const maxAttempts = 60;
    let attempts = 0;

    const poll = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/results/${id}`);
        if (res.ok) {
          const data = await res.json();
          if (data.status === 'completed' || data.status === 'failed') {
            setResults(data);
            setIsAnalyzing(false);
            return;
          }
        }
        attempts++;
        if (attempts < maxAttempts) {
          setTimeout(poll, 5000);
        } else {
          setIsAnalyzing(false);
          alert('Analysis timed out');
        }
      } catch (err) {
        console.error('Polling error:', err);
        setIsAnalyzing(false);
      }
    };
    poll();
  };

  // --- SESSION MGMT ---
  const clearSession = async () => {
    if (analysisId) {
      try {
        await fetch(`${API_BASE_URL}/results/${analysisId}`, { method: 'DELETE' });
      } catch (err) {
        console.error('Clear session error:', err);
      }
    }
    setHeaders('');
    setUrls('');
    setSelectedFile(null);
    setLogs([]);
    setResults(null);
    setAnalysisId(null);
    setIsAnalyzing(false);
    setExpandedSections({});
    if (fileInputRef.current) fileInputRef.current.value = '';
    if (wsConnection) {
      wsConnection.close();
      setWsConnection(null);
    }
  };

  const exportResults = () => {
    if (!results) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `analysis-${results.analysis_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const toggleSection = (s) => setExpandedSections(prev => ({ ...prev, [s]: !prev[s] }));

  const getRiskColor = (lvl) => {
    switch (lvl?.toLowerCase()) {
      case 'high': return 'text-red-600 bg-red-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-green-600 bg-green-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusIcon = (s) => {
    switch (s) {
      case 'completed': return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'failed': return <XCircle className="w-5 h-5 text-red-500" />;
      case 'running': return <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />;
      default: return null;
    }
  };

  const getAuthStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'pass':
      case 'present':
        return 'bg-green-100 text-green-800';
      case 'fail':
        return 'bg-red-100 text-red-800';
      case 'softfail':
      case 'neutral':
        return 'bg-yellow-100 text-yellow-800';
      case 'not_found':
      case 'unknown':
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
      <div className="min-h-screen bg-gray-50">
        {/* Header */}
        <div className="bg-white shadow-sm border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-16">
              <div className="flex items-center space-x-3">
                <Shield className="w-8 h-8 text-blue-600" />
                <h1 className="text-xl font-semibold text-gray-900">Email Security Analysis Tool</h1>
              </div>
              <div className="flex items-center space-x-4">
                {results && (
                    <button onClick={exportResults} className="flex items-center px-3 py-2 text-sm font-medium text-gray-700 bg-white border rounded-md hover:bg-gray-50">
                      <Download className="w-4 h-4 mr-2" /> Export JSON
                    </button>
                )}
                <button onClick={clearSession} className="flex items-center px-3 py-2 text-sm font-medium text-white bg-red-600 rounded-md hover:bg-red-700">
                  <Trash2 className="w-4 h-4 mr-2" /> Clear Session
                </button>
              </div>
            </div>
          </div>
        </div>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Input Panel */}
            <div className="space-y-6">
              <div className="bg-white rounded-lg shadow">
                <div className="border-b border-gray-200">
                  <nav className="-mb-px flex space-x-8 px-6">
                    {[
                      { key: 'headers', label: 'Email Headers', icon: Mail },
                      { key: 'urls', label: 'URLs', icon: Link },
                      { key: 'files', label: 'Attachments', icon: Upload }
                    ].map(({ key, label, icon: Icon }) => (
                        <button
                            key={key}
                            onClick={() => setActiveTab(key)}
                            className={`flex items-center py-4 px-1 border-b-2 font-medium text-sm ${
                                activeTab === key
                                    ? 'border-blue-500 text-blue-600'
                                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                            }`}
                        >
                          <Icon className="w-4 h-4 mr-2" />
                          {label}
                        </button>
                    ))}
                  </nav>
                </div>

                <div className="p-6">
                  {activeTab === 'headers' && (
                      <div className="space-y-4">
                        <label className="block text-sm font-medium text-gray-700">
                          Email Headers
                        </label>
                        <textarea
                            value={headers}
                            onChange={(e) => setHeaders(e.target.value)}
                            placeholder="Paste email headers here..."
                            className="w-full h-64 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 font-mono text-sm"
                        />
                        <button
                            onClick={analyzeHeaders}
                            disabled={isAnalyzing || !headers.trim()}
                            className="w-full flex items-center justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
                        >
                          {isAnalyzing ? (
                              <>
                                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                                Analyzing...
                              </>
                          ) : (
                              <>
                                <Mail className="w-4 h-4 mr-2" />
                                Analyze Headers
                              </>
                          )}
                        </button>
                      </div>
                  )}

                  {activeTab === 'urls' && (
                      <div className="space-y-4">
                        <label className="block text-sm font-medium text-gray-700">
                          URLs (one per line)
                        </label>
                        <textarea
                            value={urls}
                            onChange={(e) => setUrls(e.target.value)}
                            placeholder="https://example.com&#10;https://suspicious-site.com&#10;..."
                            className="w-full h-64 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 font-mono text-sm"
                        />
                        <button
                            onClick={analyzeUrls}
                            disabled={isAnalyzing || !urls.trim()}
                            className="w-full flex items-center justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
                        >
                          {isAnalyzing ? (
                              <>
                                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                                Analyzing...
                              </>
                          ) : (
                              <>
                                <Link className="w-4 h-4 mr-2" />
                                Analyze URLs
                              </>
                          )}
                        </button>
                      </div>
                  )}

                  {activeTab === 'files' && (
                      <div className="space-y-4">
                        <label className="block text-sm font-medium text-gray-700">
                          Upload Attachment
                        </label>
                        <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-gray-400 transition-colors">
                          <input
                              ref={fileInputRef}
                              type="file"
                              onChange={(e) => setSelectedFile(e.target.files[0])}
                              className="hidden"
                              id="file-upload"
                          />
                          <label htmlFor="file-upload" className="cursor-pointer">
                            <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                            <div className="text-lg font-medium text-gray-900 mb-2">
                              {selectedFile ? selectedFile.name : 'Choose file to analyze'}
                            </div>
                            <div className="text-sm text-gray-500">
                              Click to select or drag and drop
                            </div>
                          </label>
                        </div>
                        <button
                            onClick={analyzeFile}
                            disabled={isAnalyzing || !selectedFile}
                            className="w-full flex items-center justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
                        >
                          {isAnalyzing ? (
                              <>
                                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                                Analyzing...
                              </>
                          ) : (
                              <>
                                <Upload className="w-4 h-4 mr-2" />
                                Analyze File
                              </>
                          )}
                        </button>
                      </div>
                  )}
                </div>
              </div>

              {/* Animated Real-time Logs */}
              {(isAnalyzing || logs.length > 0) && (
                  <div className="bg-white rounded-lg shadow">
                    <div className="px-6 py-4 border-b border-gray-200">
                      <h3 className="text-lg font-medium text-gray-900">Analysis Progress</h3>
                    </div>
                    <div className="p-6">
                      <TerminalLog logs={logs} logsEndRef={logsEndRef} />
                    </div>
                  </div>
              )}
            </div>

            {/* Results Panel */}
            <div className="space-y-6">
              {results && (
                  <div className="bg-white rounded-lg shadow">
                    <div className="px-6 py-4 border-b border-gray-200">
                      <div className="flex items-center justify-between">
                        <h3 className="text-lg font-medium text-gray-900">Analysis Results</h3>
                        <div className="flex items-center space-x-2">
                          {getStatusIcon(results.status)}
                          <span className={`text-sm font-medium ${
                              results.status === 'completed' ? 'text-green-600' :
                                  results.status === 'failed' ? 'text-red-600' :
                                      'text-blue-600'
                          }`}>
                        {results.status.charAt(0).toUpperCase() + results.status.slice(1)}
                      </span>
                        </div>
                      </div>
                    </div>

                    <div className="p-6 space-y-6">
                      {/* Summary */}
                      {results.summary && Object.keys(results.summary).length > 0 && (
                          <div className="bg-blue-50 rounded-lg p-4">
                            <h4 className="text-sm font-medium text-blue-900 mb-3">Summary</h4>
                            <div className="grid grid-cols-2 gap-4">
                              {Object.entries(results.summary).map(([key, value]) => (
                                  <div key={key}>
                                    <div className="text-xs text-blue-700 uppercase tracking-wide">
                                      {key.replace(/_/g, ' ')}
                                    </div>
                                    <div className={`text-lg font-semibold ${
                                        typeof value === 'string' && ['high', 'medium', 'low'].includes(value.toLowerCase())
                                            ? getRiskColor(value)
                                            : 'text-blue-900'
                                    } px-2 py-1 rounded`}>
                                      {value}
                                    </div>
                                  </div>
                              ))}
                            </div>
                          </div>
                      )}

                      {/* Detailed Findings */}
                      {results.findings && Object.entries(results.findings).map(([category, data]) => {
                        const isExpanded = expandedSections[category];

                        return (
                            <div key={category} className="border border-gray-200 rounded-lg">
                              <button
                                  onClick={() => toggleSection(category)}
                                  className="w-full px-4 py-3 text-left flex items-center justify-between hover:bg-gray-50"
                              >
                                <span className="font-medium text-gray-900 capitalize">
                                  {category.replace(/_/g, ' ')}
                                </span>
                                {isExpanded ? (
                                    <EyeOff className="w-4 h-4 text-gray-400" />
                                ) : (
                                    <Eye className="w-4 h-4 text-gray-400" />
                                )}
                              </button>

                              {isExpanded && (
                                  <div className="border-t border-gray-200 p-4 bg-gray-50">
                                    {category === 'headers' && data.findings && data.findings.authentication ? (
                                        <div className="space-y-4">
                                          <div className="bg-white p-4 rounded border">
                                            <h5 className="font-medium text-gray-900 mb-3">Email Authentication</h5>
                                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                              {/* SPF */}
                                              <div className="border rounded p-3">
                                                <div className="flex items-center justify-between mb-2">
                                                  <span className="font-medium text-sm">SPF</span>
                                                  <span className={`px-2 py-1 rounded text-xs font-medium ${getAuthStatusColor(data.findings.authentication.spf?.status)}`}>
                                                   {data.findings.authentication.spf?.status || 'not_found'}
                                                 </span>
                                                </div>
                                                {data.findings.authentication.spf?.raw && (
                                                    <div className="text-xs text-gray-600 font-mono bg-gray-50 p-2 rounded max-h-20 overflow-y-auto">
                                                      {data.findings.authentication.spf.raw}
                                                    </div>
                                                )}
                                              </div>

                                              {/* DKIM */}
                                              <div className="border rounded p-3">
                                                <div className="flex items-center justify-between mb-2">
                                                  <span className="font-medium text-sm">DKIM</span>
                                                  <span className={`px-2 py-1 rounded text-xs font-medium ${getAuthStatusColor(data.findings.authentication.dkim?.status)}`}>
                                                   {data.findings.authentication.dkim?.status || 'not_found'}
                                                 </span>
                                                </div>
                                                {data.findings.authentication.dkim?.raw && (
                                                    <div className="text-xs text-gray-600 font-mono bg-gray-50 p-2 rounded max-h-20 overflow-y-auto">
                                                      {data.findings.authentication.dkim.raw.substring(0, 200)}
                                                      {data.findings.authentication.dkim.raw.length > 200 && '...'}
                                                    </div>
                                                )}
                                              </div>

                                              {/* DMARC */}
                                              <div className="border rounded p-3">
                                                <div className="flex items-center justify-between mb-2">
                                                  <span className="font-medium text-sm">DMARC</span>
                                                  <span className={`px-2 py-1 rounded text-xs font-medium ${getAuthStatusColor(data.findings.authentication.dmarc?.status)}`}>
                                                   {data.findings.authentication.dmarc?.status || 'not_found'}
                                                 </span>
                                                </div>
                                                {data.findings.authentication.dmarc?.raw && (
                                                    <div className="text-xs text-gray-600 font-mono bg-gray-50 p-2 rounded max-h-20 overflow-y-auto">
                                                      {data.findings.authentication.dmarc.raw}
                                                    </div>
                                                )}
                                              </div>
                                            </div>
                                          </div>

                                          {/* Other findings */}
                                          <div className="bg-white p-4 rounded border">
                                            <h5 className="font-medium text-gray-900 mb-3">Other Findings</h5>
                                            <pre className="text-xs bg-gray-50 p-3 rounded border overflow-auto max-h-96">
                                             {JSON.stringify({
                                               parsed_headers: data.findings.parsed_headers,
                                               extracted_data: data.extracted_data
                                             }, null, 2)}
                                           </pre>
                                          </div>
                                        </div>
                                    ) : (
                                        <pre className="text-xs bg-white p-3 rounded border overflow-auto max-h-96">
                                         {JSON.stringify(data, null, 2)}
                                       </pre>
                                    )}
                                  </div>
                              )}
                            </div>
                        );
                      })}

                      {/* Error Display */}
                      {results.error && (
                          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                            <div className="flex items-center">
                              <AlertTriangle className="w-5 h-5 text-red-600 mr-2" />
                              <span className="font-medium text-red-900">Analysis Error</span>
                            </div>
                            <div className="mt-2 text-sm text-red-700">
                              {results.error}
                            </div>
                          </div>
                      )}
                    </div>
                  </div>
              )}

              {!results && !isAnalyzing && (
                  <div className="bg-white rounded-lg shadow p-8 text-center">
                    <Shield className="w-16 h-16 text-gray-300 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">
                      Ready for Analysis
                    </h3>
                    <p className="text-gray-500">
                      Choose your analysis type and submit data to get started
                    </p>
                  </div>
              )}
            </div>
          </div>
        </div>
      </div>
  );
}

export default App;