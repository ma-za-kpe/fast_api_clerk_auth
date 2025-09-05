'use client';

import { useUser } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { Building2, Code2, ArrowRight, Users, Shield, Zap, Globe, Lock, TrendingUp, Database, ExternalLink, Copy, Check, Eye, Briefcase, Settings } from 'lucide-react';
import LiveApiData from '../components/LiveApiData';

export default function HomePage() {
  const { isLoaded, isSignedIn } = useUser();
  const router = useRouter();
  const [copiedEndpoint, setCopiedEndpoint] = useState<string | null>(null);

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      router.push('/dashboard');
    }
  }, [isLoaded, isSignedIn, router]);

  const publicEndpoints = [
    {
      method: 'POST',
      path: '/api/v1/auth/signup',
      description: 'Create new user account with role selection',
      public: true,
      example: '{ "email": "dev@example.com", "password": "SecurePass123!", "user_type": "developer" }'
    },
    {
      method: 'POST', 
      path: '/api/v1/auth/signin',
      description: 'Authenticate user and sync with backend',
      public: true,
      example: '{ "clerk_token": "your_clerk_session_token" }'
    },
    {
      method: 'GET',
      path: '/api/v1/reference/tech-stacks',
      description: 'Get available technologies and frameworks',
      public: false,
      example: 'Returns: [{ "id": 1, "name": "React", "category": "Frontend" }]'
    },
    {
      method: 'GET',
      path: '/api/v1/reference/project-categories', 
      description: 'Get project category options',
      public: false,
      example: 'Returns: [{ "id": 1, "name": "Web Development", "description": "..." }]'
    },
    {
      method: 'GET',
      path: '/api/v1/reference/experience-levels',
      description: 'Get developer experience level options',
      public: false, 
      example: 'Returns: [{ "id": 1, "name": "Junior", "min_years": 0, "max_years": 2 }]'
    },
    {
      method: 'GET',
      path: '/api/v1/reference/project-scopes',
      description: 'Get project scope and duration options', 
      public: false,
      example: 'Returns: [{ "id": 1, "name": "Small", "min_months": 1, "max_months": 3 }]'
    }
  ];

  const liveApiEndpoints = [
    {
      path: '/api/v1/admin/reference/tech-stacks',
      method: 'GET',
      description: 'View all available technologies and frameworks',
      title: 'Tech Stacks',
      icon: <Code2 className="w-4 h-4" />
    },
    {
      path: '/api/v1/admin/reference/project-categories',
      method: 'GET', 
      description: 'Browse project categories and types',
      title: 'Project Categories',
      icon: <Briefcase className="w-4 h-4" />
    },
    {
      path: '/api/v1/admin/reference/experience-levels',
      method: 'GET',
      description: 'See developer experience level definitions',
      title: 'Experience Levels',
      icon: <TrendingUp className="w-4 h-4" />
    },
    {
      path: '/api/v1/admin/reference/project-scopes',
      method: 'GET',
      description: 'View project scope and duration options',
      title: 'Project Scopes', 
      icon: <Settings className="w-4 h-4" />
    },
    {
      path: '/api/v1/admin/reference/budget-types',
      method: 'GET',
      description: 'Browse budget type options',
      title: 'Budget Types',
      icon: <Database className="w-4 h-4" />
    },
    {
      path: '/api/v1/admin/reference/project-types',
      method: 'GET',
      description: 'View available project types',
      title: 'Project Types',
      icon: <Globe className="w-4 h-4" />
    }
  ];

  const copyToClipboard = async (text: string, endpoint: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedEndpoint(endpoint);
      setTimeout(() => setCopiedEndpoint(null), 2000);
    } catch (err) {
      console.error('Failed to copy text: ', err);
    }
  };

  if (!isLoaded) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-white"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
      {/* Navigation */}
      <nav className="bg-black/20 backdrop-blur-xl border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-2">
              <Globe className="w-8 h-8 text-purple-400" />
              <span className="text-xl font-bold text-white">Inception Platform</span>
            </div>
            <div className="flex items-center gap-4">
              <a
                href="/sign-in"
                className="px-4 py-2 text-white hover:text-purple-300 transition-colors"
              >
                Sign In
              </a>
              <a
                href="/sign-up"
                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
              >
                Get Started
              </a>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="text-center mb-16">
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
            Connect Companies with
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400"> Vetted Developers</span>
          </h1>
          <p className="text-xl text-gray-300 max-w-3xl mx-auto mb-8">
            The trusted platform where companies find top-tier developers and talented programmers build their careers through meaningful projects.
          </p>
          <div className="flex justify-center gap-4">
            <a
              href="/sign-up"
              className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
            >
              Start Your Journey
              <ArrowRight className="w-4 h-4" />
            </a>
            <a
              href="#how-it-works"
              className="inline-flex items-center gap-2 px-6 py-3 bg-white/10 hover:bg-white/20 border border-white/20 text-white font-medium rounded-lg transition-colors"
            >
              Learn More
            </a>
          </div>
        </div>

        {/* User Types Cards */}
        <div className="grid md:grid-cols-2 gap-8 mb-20">
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-8 hover:bg-black/40 transition-colors">
            <div className="w-16 h-16 bg-blue-500/20 rounded-xl flex items-center justify-center mb-6">
              <Building2 className="w-8 h-8 text-blue-400" />
            </div>
            <h2 className="text-2xl font-bold text-white mb-4">For Companies</h2>
            <ul className="space-y-3 mb-6">
              <li className="flex items-start gap-2">
                <Shield className="w-5 h-5 text-green-400 mt-0.5" />
                <span className="text-gray-300">Access pre-vetted, skilled developers</span>
              </li>
              <li className="flex items-start gap-2">
                <Users className="w-5 h-5 text-green-400 mt-0.5" />
                <span className="text-gray-300">Managed project delivery and support</span>
              </li>
              <li className="flex items-start gap-2">
                <TrendingUp className="w-5 h-5 text-green-400 mt-0.5" />
                <span className="text-gray-300">Scale your team on-demand</span>
              </li>
            </ul>
            <a
              href="/sign-up"
              className="inline-flex items-center gap-2 text-blue-400 hover:text-blue-300 font-medium"
            >
              Post a Project
              <ArrowRight className="w-4 h-4" />
            </a>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-8 hover:bg-black/40 transition-colors">
            <div className="w-16 h-16 bg-green-500/20 rounded-xl flex items-center justify-center mb-6">
              <Code2 className="w-8 h-8 text-green-400" />
            </div>
            <h2 className="text-2xl font-bold text-white mb-4">For Developers</h2>
            <ul className="space-y-3 mb-6">
              <li className="flex items-start gap-2">
                <Zap className="w-5 h-5 text-yellow-400 mt-0.5" />
                <span className="text-gray-300">Work on exciting, real-world projects</span>
              </li>
              <li className="flex items-start gap-2">
                <Lock className="w-5 h-5 text-yellow-400 mt-0.5" />
                <span className="text-gray-300">Secure payments and fair rates</span>
              </li>
              <li className="flex items-start gap-2">
                <TrendingUp className="w-5 h-5 text-yellow-400 mt-0.5" />
                <span className="text-gray-300">Build your reputation and earn tokens</span>
              </li>
            </ul>
            <a
              href="/sign-up"
              className="inline-flex items-center gap-2 text-green-400 hover:text-green-300 font-medium"
            >
              Join as Developer
              <ArrowRight className="w-4 h-4" />
            </a>
          </div>
        </div>

        {/* Features Section */}
        <div id="how-it-works" className="mb-20">
          <h2 className="text-3xl font-bold text-white text-center mb-12">How It Works</h2>
          <div className="grid md:grid-cols-3 gap-8">
            <div className="text-center">
              <div className="w-20 h-20 bg-purple-500/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl font-bold text-purple-400">1</span>
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Sign Up & Create Profile</h3>
              <p className="text-gray-400">Choose your role and complete your profile to get started on the platform</p>
            </div>
            <div className="text-center">
              <div className="w-20 h-20 bg-purple-500/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl font-bold text-purple-400">2</span>
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Get Matched</h3>
              <p className="text-gray-400">Companies post projects, developers bid, and our team ensures quality matches</p>
            </div>
            <div className="text-center">
              <div className="w-20 h-20 bg-purple-500/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl font-bold text-purple-400">3</span>
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Collaborate & Deliver</h3>
              <p className="text-gray-400">Work together with milestone tracking, secure payments, and ongoing support</p>
            </div>
          </div>
        </div>

        {/* API Documentation Section */}
        <div className="mb-20">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-white mb-4">Public API Access</h2>
            <p className="text-gray-300 text-lg max-w-3xl mx-auto">
              Integrate with our platform using these public endpoints. Perfect for building your own applications or automating workflows.
            </p>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            {/* Public Endpoints */}
            <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center">
                  <Globe className="w-5 h-5 text-green-400" />
                </div>
                <h3 className="text-xl font-semibold text-white">Public Endpoints</h3>
              </div>
              <p className="text-gray-400 text-sm mb-4">No authentication required</p>
              
              {publicEndpoints.filter(ep => ep.public).map((endpoint, index) => (
                <div key={index} className="mb-4 p-4 bg-white/5 border border-white/10 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-1 text-xs font-medium rounded ${
                        endpoint.method === 'GET' ? 'bg-blue-500/20 text-blue-400' : 'bg-green-500/20 text-green-400'
                      }`}>
                        {endpoint.method}
                      </span>
                      <code className="text-purple-300 text-sm font-mono">
                        http://localhost:8000{endpoint.path}
                      </code>
                    </div>
                    <button
                      onClick={() => copyToClipboard(`http://localhost:8000${endpoint.path}`, endpoint.path)}
                      className="p-1 text-gray-400 hover:text-white transition-colors"
                    >
                      {copiedEndpoint === endpoint.path ? (
                        <Check className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                  <p className="text-gray-400 text-sm mb-2">{endpoint.description}</p>
                  <code className="text-xs text-gray-500 font-mono bg-black/20 p-2 rounded block overflow-x-auto">
                    {endpoint.example}
                  </code>
                </div>
              ))}
            </div>

            {/* Authenticated Endpoints */}
            <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-orange-500/20 rounded-lg flex items-center justify-center">
                  <Database className="w-5 h-5 text-orange-400" />
                </div>
                <h3 className="text-xl font-semibold text-white">Reference Data</h3>
              </div>
              <p className="text-gray-400 text-sm mb-4">Requires authentication token</p>
              
              {publicEndpoints.filter(ep => !ep.public).map((endpoint, index) => (
                <div key={index} className="mb-4 p-4 bg-white/5 border border-white/10 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-1 text-xs font-medium rounded bg-blue-500/20 text-blue-400">
                        {endpoint.method}
                      </span>
                      <code className="text-purple-300 text-sm font-mono">
                        http://localhost:8000{endpoint.path}
                      </code>
                    </div>
                    <button
                      onClick={() => copyToClipboard(`http://localhost:8000${endpoint.path}`, endpoint.path)}
                      className="p-1 text-gray-400 hover:text-white transition-colors"
                    >
                      {copiedEndpoint === endpoint.path ? (
                        <Check className="w-4 h-4 text-green-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                  <p className="text-gray-400 text-sm mb-2">{endpoint.description}</p>
                  <code className="text-xs text-gray-500 font-mono bg-black/20 p-2 rounded block overflow-x-auto">
                    {endpoint.example}
                  </code>
                </div>
              ))}
              
              <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                <p className="text-yellow-300 text-sm">
                  <Shield className="inline w-4 h-4 mr-1" />
                  Requires Bearer token in Authorization header
                </p>
              </div>
            </div>
          </div>

          {/* API Usage Example */}
          <div className="mt-8 bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
            <h3 className="text-xl font-semibold text-white mb-4">Quick Start Example</h3>
            <div className="bg-black/50 rounded-lg p-4 overflow-x-auto">
              <pre className="text-sm">
                <code className="text-gray-300">
{`// 1. Create a new developer account
const response = await fetch('http://localhost:8000/api/v1/auth/signup', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'developer@example.com',
    password: 'SecurePassword123!',
    first_name: 'John',
    last_name: 'Doe', 
    user_type: 'developer'
  })
});

// 2. Get available tech stacks (requires auth)
const techStacks = await fetch('http://localhost:8000/api/v1/reference/tech-stacks', {
  headers: { 
    'Authorization': 'Bearer your_jwt_token',
    'Content-Type': 'application/json' 
  }
});`}
                </code>
              </pre>
            </div>
          </div>
        </div>

        {/* Live API Data Section */}
        <div className="mb-20">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-white mb-4">Explore Live Platform Data</h2>
            <p className="text-gray-300 text-lg max-w-3xl mx-auto">
              Click the buttons below to view real data from our API endpoints. Perfect for understanding our platform's reference data structure.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {liveApiEndpoints.map((endpoint, index) => (
              <LiveApiData key={index} endpoint={endpoint}>
                <div className="mt-3 text-center">
                  <p className="text-xs text-gray-500">
                    {endpoint.method} {endpoint.path}
                  </p>
                </div>
              </LiveApiData>
            ))}
          </div>

          <div className="mt-8 text-center">
            <p className="text-gray-400 text-sm">
              <Shield className="inline w-4 h-4 mr-1" />
              These endpoints require authentication. Sign up to access live data.
            </p>
          </div>
        </div>

        {/* CTA Section */}
        <div className="bg-gradient-to-r from-purple-600/20 to-pink-600/20 border border-purple-500/30 rounded-2xl p-12 text-center">
          <h2 className="text-3xl font-bold text-white mb-4">Ready to Get Started?</h2>
          <p className="text-gray-300 text-lg mb-8 max-w-2xl mx-auto">
            Join thousands of companies and developers building the future together
          </p>
          <div className="flex justify-center gap-4">
            <a
              href="/sign-up"
              className="inline-flex items-center gap-2 px-6 py-3 bg-white text-purple-900 font-medium rounded-lg hover:bg-gray-100 transition-colors"
            >
              Create Account
              <ArrowRight className="w-4 h-4" />
            </a>
            <a
              href="/sign-in"
              className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
            >
              Sign In
            </a>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="bg-black/30 border-t border-white/10 py-8 mt-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="flex items-center gap-2 mb-4 md:mb-0">
              <Globe className="w-6 h-6 text-purple-400" />
              <span className="text-white font-medium">Inception Platform</span>
            </div>
            <p className="text-gray-400 text-sm">
              © 2024 Inception Platform. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}