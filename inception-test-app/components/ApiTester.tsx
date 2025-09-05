'use client';

import { useState } from 'react';
import { Play, Copy, Check, Loader2, AlertCircle, CheckCircle } from 'lucide-react';

interface ApiTesterProps {
  endpoint: {
    method: string;
    path: string;
    description: string;
    example: string;
    public: boolean;
  };
}

export default function ApiTester({ endpoint }: ApiTesterProps) {
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [requestBody, setRequestBody] = useState(
    endpoint.method === 'POST' ? endpoint.example : ''
  );

  const testEndpoint = async () => {
    setLoading(true);
    setError(null);
    setResponse(null);

    try {
      const url = `http://localhost:8000${endpoint.path}`;
      const options: RequestInit = {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/json',
        },
      };

      if (endpoint.method === 'POST' && requestBody) {
        options.body = requestBody;
      }

      // Add auth header for protected endpoints
      if (!endpoint.public) {
        // For demo purposes, we'll show what the request would look like
        setError('This endpoint requires authentication. Sign in to test it.');
        return;
      }

      const res = await fetch(url, options);
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || `HTTP ${res.status}`);
      }

      setResponse(data);
    } catch (err: any) {
      setError(err.message || 'Request failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="border-t border-white/10 pt-3 mt-3">
      <div className="flex items-center gap-2 mb-3">
        <button
          onClick={testEndpoint}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-1 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-800 text-white text-sm font-medium rounded transition-colors"
        >
          {loading ? (
            <Loader2 className="w-3 h-3 animate-spin" />
          ) : (
            <Play className="w-3 h-3" />
          )}
          Test API
        </button>
        <span className="text-xs text-gray-500">Try it now</span>
      </div>

      {endpoint.method === 'POST' && (
        <div className="mb-3">
          <label className="block text-xs font-medium text-gray-400 mb-1">Request Body:</label>
          <textarea
            value={requestBody}
            onChange={(e) => setRequestBody(e.target.value)}
            rows={3}
            className="w-full px-2 py-1 bg-black/30 border border-white/20 rounded text-white text-xs font-mono focus:outline-none focus:border-purple-400"
            placeholder="Enter JSON request body..."
          />
        </div>
      )}

      {loading && (
        <div className="flex items-center gap-2 p-2 bg-blue-500/10 border border-blue-500/20 rounded text-blue-300 text-xs">
          <Loader2 className="w-3 h-3 animate-spin" />
          Testing endpoint...
        </div>
      )}

      {error && (
        <div className="flex items-start gap-2 p-2 bg-red-500/10 border border-red-500/20 rounded text-red-300 text-xs">
          <AlertCircle className="w-3 h-3 mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {response && (
        <div className="bg-green-500/10 border border-green-500/20 rounded">
          <div className="flex items-center gap-2 p-2 border-b border-green-500/20">
            <CheckCircle className="w-3 h-3 text-green-400" />
            <span className="text-green-300 text-xs font-medium">Response</span>
          </div>
          <pre className="text-xs text-gray-300 p-2 overflow-x-auto">
            {JSON.stringify(response, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}