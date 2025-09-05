'use client';

import { useState } from 'react';
import { Eye, X, Loader2, AlertCircle, Database, Users, Briefcase, Code2, Settings, Building2 } from 'lucide-react';

interface LiveApiDataProps {
  endpoint: {
    path: string;
    method: string;
    description: string;
    title: string;
    icon?: React.ReactNode;
  };
  children: React.ReactNode;
}

export default function LiveApiData({ endpoint, children }: LiveApiDataProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    if (isOpen) {
      setIsOpen(false);
      return;
    }

    setLoading(true);
    setError(null);
    setData(null);

    try {
      const url = `http://localhost:8000${endpoint.path}`;
      const options: RequestInit = {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/json',
        },
      };

      const res = await fetch(url, options);
      
      if (!res.ok) {
        if (res.status === 401) {
          throw new Error('Authentication required - Sign in to view this data');
        }
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `HTTP ${res.status}: ${res.statusText}`);
      }

      const responseData = await res.json();
      setData(responseData);
      setIsOpen(true);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch data');
    } finally {
      setLoading(false);
    }
  };

  const renderData = () => {
    if (!data) return null;

    // Handle different data structures
    if (Array.isArray(data)) {
      return (
        <div className="space-y-3">
          <p className="text-gray-400 text-sm">{data.length} items found</p>
          {data.slice(0, 10).map((item, index) => (
            <div key={index} className="p-3 bg-white/5 border border-white/10 rounded-lg">
              {Object.entries(item).map(([key, value]) => (
                <div key={key} className="flex justify-between items-center">
                  <span className="text-gray-400 text-sm capitalize">{key.replace('_', ' ')}:</span>
                  <span className="text-white text-sm font-medium">
                    {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value)}
                  </span>
                </div>
              ))}
            </div>
          ))}
          {data.length > 10 && (
            <p className="text-gray-500 text-sm text-center">+ {data.length - 10} more items</p>
          )}
        </div>
      );
    }

    // Handle object data
    if (typeof data === 'object') {
      return (
        <div className="space-y-2">
          {Object.entries(data).map(([key, value]) => (
            <div key={key} className="flex justify-between items-center p-2 bg-white/5 rounded">
              <span className="text-gray-400 text-sm capitalize">{key.replace('_', ' ')}:</span>
              <span className="text-white text-sm font-medium">
                {typeof value === 'object' ? JSON.stringify(value) : String(value)}
              </span>
            </div>
          ))}
        </div>
      );
    }

    return (
      <pre className="text-sm text-gray-300 bg-black/30 p-3 rounded overflow-auto">
        {JSON.stringify(data, null, 2)}
      </pre>
    );
  };

  return (
    <div className="space-y-4">
      {/* Trigger Button */}
      <button
        onClick={fetchData}
        disabled={loading}
        className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 disabled:from-gray-600 disabled:to-gray-700 text-white font-medium rounded-lg transition-all"
      >
        {loading ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : isOpen ? (
          <X className="w-4 h-4" />
        ) : (
          endpoint.icon || <Eye className="w-4 h-4" />
        )}
        {loading ? 'Loading...' : isOpen ? 'Close' : `View ${endpoint.title}`}
      </button>

      {/* Error Display */}
      {error && (
        <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
          <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-red-300 text-sm font-medium">Error</p>
            <p className="text-red-400 text-sm">{error}</p>
            {error.includes('Authentication required') && (
              <p className="text-red-500 text-xs mt-1">
                <a href="/sign-up" className="underline hover:no-underline">
                  Sign up
                </a> or <a href="/sign-in" className="underline hover:no-underline">
                  sign in
                </a> to view this data
              </p>
            )}
          </div>
        </div>
      )}

      {/* Data Display */}
      {isOpen && data && (
        <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-4 max-h-96 overflow-y-auto">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-lg font-semibold text-white">{endpoint.title}</h4>
            <button
              onClick={() => setIsOpen(false)}
              className="p-1 text-gray-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <p className="text-gray-400 text-sm mb-4">{endpoint.description}</p>
          {renderData()}
        </div>
      )}

      {/* Additional content */}
      {children}
    </div>
  );
}