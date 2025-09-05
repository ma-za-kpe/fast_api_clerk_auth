'use client';

import { useEffect } from 'react';
import { useUser } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import { Users, UserPlus, Shield, Search, Filter, ArrowLeft, UserCog } from 'lucide-react';

export default function AdminUsersPage() {
  const { isLoaded, isSignedIn, user } = useUser();
  const router = useRouter();

  useEffect(() => {
    if (isLoaded && !isSignedIn) {
      router.push('/sign-in');
    }
  }, [isLoaded, isSignedIn]);

  useEffect(() => {
    // Check if user is admin
    if (isLoaded && isSignedIn && user) {
      const isAdmin = user?.publicMetadata?.is_admin;
      if (!isAdmin) {
        router.push('/dashboard');
      }
    }
  }, [isLoaded, isSignedIn, user]);

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
            <div className="flex items-center gap-8">
              <div className="flex items-center gap-2">
                <Shield className="w-8 h-8 text-purple-400" />
                <span className="text-xl font-bold text-white">Admin Panel</span>
              </div>
              <div className="flex items-center gap-6">
                <a href="/admin/dashboard" className="text-gray-300 hover:text-white">Overview</a>
                <a href="/admin/users" className="text-white font-medium">Users</a>
                <a href="/admin/analytics" className="text-gray-300 hover:text-white">Analytics</a>
              </div>
            </div>
            <button
              onClick={() => router.push('/admin/dashboard')}
              className="px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white text-sm transition-colors"
            >
              Back to Dashboard
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center">
          {/* Header */}
          <div className="mb-8">
            <button
              onClick={() => router.push('/admin/dashboard')}
              className="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-6 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Admin Dashboard
            </button>
            <h1 className="text-4xl font-bold text-white mb-4">User Management</h1>
            <p className="text-gray-300 text-lg">
              Manage users, roles, permissions, and access control
            </p>
          </div>

          {/* Coming Soon Card */}
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-12 max-w-3xl mx-auto">
            <div className="flex justify-center mb-8">
              <div className="relative">
                <div className="w-32 h-32 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-full opacity-20 animate-pulse"></div>
                <div className="absolute inset-0 flex items-center justify-center">
                  <Users className="w-16 h-16 text-blue-400" />
                </div>
              </div>
            </div>

            <h2 className="text-2xl font-semibold text-white mb-4">
              User Management Interface Coming Soon
            </h2>
            
            <p className="text-gray-300 mb-8 leading-relaxed">
              We're developing a powerful user management system to help you efficiently manage users, 
              assign roles, control permissions, and monitor user activity across the platform.
            </p>

            {/* Feature Preview */}
            <div className="grid md:grid-cols-3 gap-6 text-left">
              <div className="bg-white/5 border border-white/10 rounded-lg p-4">
                <UserPlus className="w-8 h-8 text-green-400 mb-3" />
                <h3 className="text-white font-medium mb-1">User Directory</h3>
                <p className="text-gray-400 text-sm">
                  Search, filter, and manage all platform users
                </p>
              </div>
              <div className="bg-white/5 border border-white/10 rounded-lg p-4">
                <Shield className="w-8 h-8 text-purple-400 mb-3" />
                <h3 className="text-white font-medium mb-1">Role Management</h3>
                <p className="text-gray-400 text-sm">
                  Assign and manage user roles and permissions
                </p>
              </div>
              <div className="bg-white/5 border border-white/10 rounded-lg p-4">
                <UserCog className="w-8 h-8 text-orange-400 mb-3" />
                <h3 className="text-white font-medium mb-1">Access Control</h3>
                <p className="text-gray-400 text-sm">
                  Fine-grained access control and audit logs
                </p>
              </div>
            </div>

            {/* Coming Soon Badge */}
            <div className="mt-8">
              <span className="inline-flex items-center gap-2 px-4 py-2 bg-blue-500/20 border border-blue-500/40 rounded-full text-blue-300 text-sm">
                <Users className="w-4 h-4 animate-pulse" />
                Under Construction
              </span>
            </div>
          </div>

          {/* Additional Info */}
          <div className="mt-8 text-gray-400 text-sm">
            <p>Expected launch: Q1 2025</p>
            <p className="mt-2">
              For urgent user management needs, contact system administrator.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}