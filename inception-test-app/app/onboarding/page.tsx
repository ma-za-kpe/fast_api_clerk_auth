'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useUser } from '@clerk/nextjs';
import useApi from '@/hooks/useApi';
import { Loader2 } from 'lucide-react';

export default function OnboardingPage() {
  const { isLoaded, isSignedIn, user } = useUser();
  const router = useRouter();
  const api = useApi();
  const [status, setStatus] = useState('Initializing...');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isLoaded && isSignedIn && user) {
      syncUserWithBackend();
    }
  }, [isLoaded, isSignedIn, user]);

  const syncUserWithBackend = async () => {
    try {
      setStatus('Syncing with backend...');
      
      // Get the user type from localStorage (set during signup)
      const pendingUserType = localStorage.getItem('pendingUserType') || 'client';
      
      // First, create the user in the backend with the selected user type
      setStatus('Creating your account...');
      try {
        // Generate a stronger password that meets all requirements
        const strongPassword = `Clerk@${Date.now()}#Managed$2024!`;
        
        await api.callApi('/auth/signup', {
          method: 'POST',
          body: JSON.stringify({
            email: user.primaryEmailAddress?.emailAddress,
            password: strongPassword, // Strong password that avoids sequential characters
            first_name: user.firstName || '',
            last_name: user.lastName || '',
            user_type: pendingUserType,
          }),
        });
        console.log('User profile created successfully');
      } catch (signupError: any) {
        console.error('Signup error:', signupError);
        
        // Check if it's a validation error
        if (signupError.message?.includes('validation')) {
          setError(`Account setup failed: ${signupError.message}. Please contact support.`);
          
          // Try to create just the user type profile directly
          try {
            setStatus('Setting up user profile...');
            await api.callApi('/auth/create-user-type-profile', {
              method: 'POST', 
              body: JSON.stringify({
                user_type: pendingUserType, // Keep lowercase
              }),
            });
            console.log('User type profile created via fallback');
          } catch (profileError) {
            console.error('Failed to create user type profile:', profileError);
          }
        } else if (!signupError.message?.includes('already exists')) {
          // Only show error if it's not a "user exists" error
          setError(`Failed to complete setup: ${signupError.message}`);
        }
        
        console.log('Continuing despite signup error...');
      }

      // Sync with backend using Clerk token
      setStatus('Authenticating...');
      const syncResult = await api.auth.syncWithBackend();
      console.log('Backend sync successful:', syncResult);

      // Clear the pending user type
      localStorage.removeItem('pendingUserType');

      // Get user details to determine routing
      const userDetails = await api.auth.me();
      const userType = userDetails.user_type;

      setStatus('Redirecting to your dashboard...');

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
          router.push('/dashboard');
      }
    } catch (err: any) {
      console.error('Onboarding error:', err);
      setError(err.message || 'Failed to complete onboarding');
      // Still redirect after a delay even if sync fails
      setTimeout(() => {
        router.push('/dashboard');
      }, 3000);
    }
  };

  if (!isLoaded) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
        <div className="text-center">
          <Loader2 className="w-12 h-12 text-white animate-spin mx-auto mb-4" />
          <p className="text-white">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isSignedIn) {
    router.push('/sign-in');
    return null;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
      <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-8 max-w-md w-full">
        <div className="text-center">
          <Loader2 className="w-12 h-12 text-purple-400 animate-spin mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-white mb-2">Setting up your account</h2>
          <p className="text-gray-300 mb-4">{status}</p>
          {error && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 mt-4">
              <p className="text-red-400 text-sm">{error}</p>
              <p className="text-gray-400 text-xs mt-2">Redirecting to dashboard...</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}