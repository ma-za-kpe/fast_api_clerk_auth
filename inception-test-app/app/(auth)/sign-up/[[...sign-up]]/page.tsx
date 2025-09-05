'use client';

import { SignUp } from '@clerk/nextjs';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Building2, Code2, Users, Shield, ClipboardCheck, Bug, Settings } from 'lucide-react';

const userTypes = [
  {
    id: 'client',
    name: 'Client',
    description: 'Post projects and hire developers',
    icon: Building2,
    color: 'bg-blue-500',
  },
  {
    id: 'developer',
    name: 'Developer',
    description: 'Work on projects and earn',
    icon: Code2,
    color: 'bg-green-500',
  },
  {
    id: 'engineering_manager',
    name: 'Engineering Manager',
    description: 'Vet developers and match projects',
    icon: Users,
    color: 'bg-purple-500',
  },
  {
    id: 'delivery_manager',
    name: 'Delivery Manager',
    description: 'Manage project delivery',
    icon: ClipboardCheck,
    color: 'bg-orange-500',
  },
  {
    id: 'tech_lead',
    name: 'Tech Lead',
    description: 'Technical oversight and mentoring',
    icon: Shield,
    color: 'bg-indigo-500',
  },
  {
    id: 'qa_lead',
    name: 'QA Lead',
    description: 'Quality assurance and testing',
    icon: Bug,
    color: 'bg-red-500',
  },
  {
    id: 'admin',
    name: 'Admin',
    description: 'Platform administration',
    icon: Settings,
    color: 'bg-gray-600',
  },
];

export default function SignUpPage() {
  const [selectedUserType, setSelectedUserType] = useState<string>('');
  const [showSignUp, setShowSignUp] = useState(false);
  const router = useRouter();

  const handleUserTypeSelect = (type: string) => {
    setSelectedUserType(type);
    // Store user type for after signup
    localStorage.setItem('pendingUserType', type);
    setShowSignUp(true);
  };

  const [formData, setFormData] = useState({
    email: '',
    password: '',
    firstName: '',
    lastName: '',
    username: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setErrorMessage('');

    try {
      // Call backend signup endpoint which creates both Clerk user AND user_type_profile
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1'}/auth/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: formData.email,
          password: formData.password,
          username: formData.username,
          first_name: formData.firstName,
          last_name: formData.lastName,
          user_type: selectedUserType, // Keep as lowercase - backend expects lowercase
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        // Handle validation errors (422) with detailed messages
        if (response.status === 422 && data.detail && Array.isArray(data.detail)) {
          const validationErrors = data.detail.map((err: any) => {
            const field = err.loc ? err.loc[err.loc.length - 1] : 'unknown';
            return `${field}: ${err.msg}`;
          }).join('; ');
          throw new Error(`Validation failed: ${validationErrors}`);
        }
        throw new Error(data.detail || 'Signup failed');
      }

      // Success! User created with user_type_profile
      // The user is automatically signed in by Clerk after successful creation
      // Redirect based on user type
      const redirectMap: Record<string, string> = {
        'client': '/client/dashboard',
        'developer': '/developer/dashboard',
        'admin': '/admin/dashboard',
      };
      
      // Small delay to ensure Clerk session is established
      setTimeout(() => {
        router.push(redirectMap[selectedUserType] || '/dashboard');
      }, 1000);
    } catch (error: any) {
      setErrorMessage(error.message || 'Failed to create account');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (showSignUp) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900 p-4">
        <div className="w-full max-w-md">
          <div className="text-center mb-6">
            <h1 className="text-3xl font-bold text-white mb-2">
              Sign Up as {userTypes.find(t => t.id === selectedUserType)?.name}
            </h1>
            <button
              onClick={() => {
                setShowSignUp(false);
                setSelectedUserType('');
                setFormData({ email: '', password: '', firstName: '', lastName: '', username: '' });
              }}
              className="text-gray-300 hover:text-white underline text-sm"
            >
              Choose different role
            </button>
          </div>
          
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
            <form onSubmit={handleSignup} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">First Name</label>
                  <input
                    type="text"
                    required
                    value={formData.firstName}
                    onChange={(e) => setFormData({ ...formData, firstName: e.target.value })}
                    className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                    placeholder="John"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Last Name</label>
                  <input
                    type="text"
                    required
                    value={formData.lastName}
                    onChange={(e) => setFormData({ ...formData, lastName: e.target.value })}
                    className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                    placeholder="Doe"
                  />
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Username</label>
                <input
                  type="text"
                  required
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                  placeholder="johndoe"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Email</label>
                <input
                  type="email"
                  required
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                  placeholder="john@example.com"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
                <input
                  type="password"
                  required
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                  placeholder="••••••••"
                />
                <p className="text-xs text-gray-400 mt-1">
                  Must be 8+ characters with uppercase, lowercase, number & special character
                </p>
              </div>

              {errorMessage && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                  <p className="text-red-400 text-sm">{errorMessage}</p>
                </div>
              )}

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-800 text-white font-medium rounded-lg transition-colors"
              >
                {isSubmitting ? 'Creating Account...' : 'Create Account'}
              </button>
            </form>

            <div className="mt-4 text-center">
              <p className="text-gray-400 text-sm">
                Already have an account?{' '}
                <a href="/sign-in" className="text-purple-400 hover:text-purple-300 underline">
                  Sign in
                </a>
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Keep the existing SignUp component as fallback
  if (false && showSignUp) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900 p-4">
        <div className="w-full max-w-md">
          <div className="text-center mb-6">
            <h1 className="text-3xl font-bold text-white mb-2">
              Sign Up as {userTypes.find(t => t.id === selectedUserType)?.name}
            </h1>
            <button
              onClick={() => {
                setShowSignUp(false);
                setSelectedUserType('');
              }}
              className="text-gray-300 hover:text-white underline text-sm"
            >
              Choose different role
            </button>
          </div>
          <SignUp 
            routing="path" 
            path="/sign-up"
            signInUrl="/sign-in"
            fallbackRedirectUrl="/onboarding"
            forceRedirectUrl="/onboarding"
            appearance={{
              elements: {
                rootBox: "mx-auto",
                card: "bg-black/30 backdrop-blur-xl border border-white/10",
                headerTitle: "text-white",
                headerSubtitle: "text-gray-400",
                socialButtonsBlockButton: "bg-white/10 border-white/20 text-white hover:bg-white/20",
                dividerLine: "bg-white/20",
                dividerText: "text-gray-400",
                formFieldLabel: "text-gray-300",
                formFieldInput: "bg-white/10 border-white/20 text-white placeholder:text-gray-500",
                formButtonPrimary: "bg-purple-600 hover:bg-purple-700",
                footerActionLink: "text-purple-400 hover:text-purple-300",
                formFieldInputShowPasswordButton: "text-gray-400 hover:text-white",
                identityPreviewText: "text-gray-300",
                identityPreviewEditButton: "text-purple-400 hover:text-purple-300",
                formResendCodeLink: "text-purple-400 hover:text-purple-300",
              }
            }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900 p-4">
      <div className="w-full max-w-4xl">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-white mb-3">Join Inception Platform</h1>
          <p className="text-gray-300 text-lg">Choose your role to get started</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {userTypes.slice(0, 2).map((type) => {
            const Icon = type.icon;
            return (
              <button
                key={type.id}
                onClick={() => handleUserTypeSelect(type.id)}
                className="group relative bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6 text-left hover:bg-black/40 hover:border-white/20 transition-all"
              >
                <div className={`${type.color} w-12 h-12 rounded-lg flex items-center justify-center mb-4`}>
                  <Icon className="w-6 h-6 text-white" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-2">{type.name}</h3>
                <p className="text-gray-400 text-sm">{type.description}</p>
              </button>
            );
          })}
        </div>

        {/* Manager roles - smaller section */}
        <div className="mt-8">
          <p className="text-center text-gray-400 text-sm mb-4">Internal Team Roles</p>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {userTypes.slice(2).map((type) => {
              const Icon = type.icon;
              return (
                <button
                  key={type.id}
                  onClick={() => handleUserTypeSelect(type.id)}
                  className="group bg-black/20 backdrop-blur-xl border border-white/5 rounded-lg p-3 text-center hover:bg-black/30 hover:border-white/10 transition-all"
                >
                  <div className={`${type.color} w-8 h-8 rounded-lg flex items-center justify-center mx-auto mb-2 opacity-70`}>
                    <Icon className="w-4 h-4 text-white" />
                  </div>
                  <p className="text-white text-xs font-medium">{type.name}</p>
                </button>
              );
            })}
          </div>
        </div>

        <div className="mt-8 text-center">
          <p className="text-gray-400 text-sm">
            Already have an account?{' '}
            <a href="/sign-in" className="text-purple-400 hover:text-purple-300 underline">
              Sign in
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}