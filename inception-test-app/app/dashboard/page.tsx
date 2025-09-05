'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useUser } from '@clerk/nextjs';
import useApi from '@/hooks/useApi';
import { Loader2 } from 'lucide-react';

export default function DashboardPage() {
  const { isLoaded, isSignedIn, user } = useUser();
  const router = useRouter();
  const api = useApi();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      redirectToRoleDashboard();
    }
  }, [isLoaded, isSignedIn]);

  const redirectToRoleDashboard = async () => {
    try {
      // Check if user is admin first (from public metadata)
      if (user?.publicMetadata?.is_admin) {
        // Check if they're trying to go to admin dashboard
        const currentPath = window.location.pathname;
        if (currentPath.includes('/admin')) {
          return; // Don't redirect if already on admin path
        }
      }

      // Sync with backend and get user details
      await api.auth.syncWithBackend();
      const userDetails = await api.auth.me();
      const userType = userDetails.user_type;

      // Route based on user type
      switch(userType) {
        case 'client':
          router.push('/client/dashboard');
          break;
        case 'developer':
          router.push('/developer/dashboard');
          break;
        case 'engineering_manager':
          router.push('/engineering/dashboard');
          break;
        case 'delivery_manager':
          router.push('/delivery/dashboard');
          break;
        case 'tech_lead':
          router.push('/tech-lead/dashboard');
          break;
        case 'qa_lead':
          router.push('/qa/dashboard');
          break;
        case 'admin':
          router.push('/admin/dashboard');
          break;
        default:
          // If no specific user type, show general dashboard
          setLoading(false);
      }
    } catch (error) {
      console.error('Failed to get user details:', error);
      setLoading(false);
    }
  };

  if (!isLoaded || loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
        <div className="text-center">
          <Loader2 className="w-12 h-12 text-white animate-spin mx-auto mb-4" />
          <p className="text-white">Loading your dashboard...</p>
        </div>
      </div>
    );
  }

  if (!isSignedIn) {
    router.push('/sign-in');
    return null;
  }

  // Fallback dashboard if user type is not set
  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-8">
          <h1 className="text-3xl font-bold text-white mb-4">Welcome to Inception Platform</h1>
          <p className="text-gray-300 mb-6">
            Your account is being set up. Please complete your profile to get started.
          </p>
          <div className="grid gap-4">
            <a
              href="/client/dashboard"
              className="block bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg p-4 transition-colors"
            >
              <h3 className="text-lg font-semibold text-white mb-1">Client Dashboard</h3>
              <p className="text-gray-400 text-sm">Post projects and hire developers</p>
            </a>
            <a
              href="/developer/dashboard"
              className="block bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg p-4 transition-colors"
            >
              <h3 className="text-lg font-semibold text-white mb-1">Developer Dashboard</h3>
              <p className="text-gray-400 text-sm">Browse projects and submit bids</p>
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}