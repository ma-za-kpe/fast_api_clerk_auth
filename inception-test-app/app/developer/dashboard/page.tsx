'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { Code2, Plus, Briefcase, DollarSign, Clock, Star, TrendingUp, AlertCircle, CheckCircle, XCircle, Loader2, Coins } from 'lucide-react';
import { DeveloperProfile, Project } from '@/types';

export default function DeveloperDashboard() {
  const { isLoaded, isSignedIn, user } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [profile, setProfile] = useState<DeveloperProfile | null>(null);
  const [availableProjects, setAvailableProjects] = useState<Project[]>([]);
  const [stats, setStats] = useState({
    activeProjects: 3,
    totalEarned: 45000,
    completedProjects: 12,
    avgRating: 4.8,
    tokens: 125,
  });

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      loadDashboardData();
    }
  }, [isLoaded, isSignedIn]);

  const loadDashboardData = async () => {
    try {
      // Sync with backend
      await api.auth.syncWithBackend();
      
      // Get developer profile
      try {
        const profileData = await api.developers.getProfile();
        setProfile(profileData);
      } catch (error) {
        console.log('No developer profile yet');
      }

      // Get available projects
      try {
        const projectsData = await api.projects.getAvailable();
        setAvailableProjects(projectsData.items || []);
      } catch (error) {
        console.log('No available projects');
      }
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getVettingStatusBadge = () => {
    if (!profile) return null;
    
    switch (profile.vetting_status) {
      case 'approved':
        return (
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-green-500/20 border border-green-500/30 rounded-full">
            <CheckCircle className="w-4 h-4 text-green-400" />
            <span className="text-green-400 text-sm font-medium">Verified Developer</span>
          </div>
        );
      case 'pending':
        return (
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-yellow-500/20 border border-yellow-500/30 rounded-full">
            <Clock className="w-4 h-4 text-yellow-400" />
            <span className="text-yellow-400 text-sm font-medium">Vetting Pending</span>
          </div>
        );
      case 'rejected':
        return (
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-red-500/20 border border-red-500/30 rounded-full">
            <XCircle className="w-4 h-4 text-red-400" />
            <span className="text-red-400 text-sm font-medium">Vetting Required</span>
          </div>
        );
      default:
        return null;
    }
  };

  if (!isLoaded || loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
        <Loader2 className="w-12 h-12 text-white animate-spin" />
      </div>
    );
  }

  if (!isSignedIn) {
    router.push('/sign-in');
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
      {/* Navigation */}
      <nav className="bg-black/20 backdrop-blur-xl border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-8">
              <div className="flex items-center gap-2">
                <Code2 className="w-8 h-8 text-green-400" />
                <span className="text-xl font-bold text-white">Inception Developer</span>
              </div>
              <div className="flex gap-6">
                <a href="/developer/dashboard" className="text-white font-medium">Dashboard</a>
                <a href="/developer/profile" className="text-gray-300 hover:text-white">Profile</a>
                <a href="/developer/projects" className="text-gray-300 hover:text-white">Browse Projects</a>
                <a href="/developer/my-projects" className="text-gray-300 hover:text-white">My Projects</a>
                <a href="/developer/earnings" className="text-gray-300 hover:text-white">Earnings</a>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 px-3 py-1 bg-purple-500/20 border border-purple-500/30 rounded-full">
                <Coins className="w-4 h-4 text-purple-400" />
                <span className="text-purple-400 font-medium">{stats.tokens} tokens</span>
              </div>
              <span className="text-sm text-gray-300">
                {user?.firstName} {user?.lastName}
              </span>
              <button
                onClick={() => signOut()}
                className="px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white text-sm transition-colors"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Profile Status Alert */}
        {!profile && (
          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-6 mb-8">
            <h2 className="text-xl font-semibold text-yellow-300 mb-2">Complete Your Profile</h2>
            <p className="text-gray-300 mb-4">
              Create your developer profile to start bidding on projects and get vetted by our team.
            </p>
            <a
              href="/developer/profile"
              className="inline-flex items-center gap-2 px-4 py-2 bg-yellow-500 hover:bg-yellow-600 text-black font-medium rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              Create Developer Profile
            </a>
          </div>
        )}

        {profile && profile.vetting_status === 'pending' && (
          <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4 mb-8">
            <div className="flex items-center gap-3">
              <AlertCircle className="w-5 h-5 text-blue-400" />
              <div>
                <p className="text-blue-300 font-medium">Profile Under Review</p>
                <p className="text-gray-400 text-sm">Our team is reviewing your profile. You'll be notified once approved.</p>
              </div>
            </div>
          </div>
        )}

        {profile && profile.vetting_status === 'rejected' && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 mb-8">
            <div className="flex items-center gap-3">
              <XCircle className="w-5 h-5 text-red-400" />
              <div>
                <p className="text-red-300 font-medium">Profile Needs Attention</p>
                <p className="text-gray-400 text-sm">
                  Please update your profile based on the feedback: {profile.vetting_notes || 'Check your email for details'}
                </p>
                <a href="/developer/profile" className="text-red-400 hover:text-red-300 text-sm underline">
                  Update Profile
                </a>
              </div>
            </div>
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                <DollarSign className="w-6 h-6 text-green-400" />
              </div>
            </div>
            <p className="text-2xl font-bold text-white">${stats.totalEarned.toLocaleString()}</p>
            <p className="text-gray-400 text-sm">Total Earned</p>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                <Briefcase className="w-6 h-6 text-blue-400" />
              </div>
            </div>
            <p className="text-2xl font-bold text-white">{stats.activeProjects}</p>
            <p className="text-gray-400 text-sm">Active Projects</p>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                <CheckCircle className="w-6 h-6 text-purple-400" />
              </div>
            </div>
            <p className="text-2xl font-bold text-white">{stats.completedProjects}</p>
            <p className="text-gray-400 text-sm">Completed</p>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                <Star className="w-6 h-6 text-yellow-400" />
              </div>
            </div>
            <p className="text-2xl font-bold text-white">{stats.avgRating}</p>
            <p className="text-gray-400 text-sm">Avg Rating</p>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-orange-500/20 rounded-lg flex items-center justify-center">
                <TrendingUp className="w-6 h-6 text-orange-400" />
              </div>
            </div>
            <p className="text-2xl font-bold text-white">85%</p>
            <p className="text-gray-400 text-sm">Success Rate</p>
          </div>
        </div>

        {/* Profile Summary */}
        {profile && (
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6 mb-8">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <h2 className="text-xl font-semibold text-white">Profile Summary</h2>
                {getVettingStatusBadge()}
              </div>
              <a
                href="/developer/profile"
                className="text-purple-400 hover:text-purple-300 text-sm"
              >
                Edit Profile
              </a>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <p className="text-gray-400 text-sm mb-1">Primary Role</p>
                <p className="text-white font-medium">{profile.primary_role}</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm mb-1">Experience</p>
                <p className="text-white font-medium">{profile.years_experience} years</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm mb-1">Hourly Rate</p>
                <p className="text-white font-medium">${profile.hourly_rate || 'Not set'}/hr</p>
              </div>
              <div>
                <p className="text-gray-400 text-sm mb-1">Availability</p>
                <p className={`font-medium ${
                  profile.availability_status === 'available' ? 'text-green-400' :
                  profile.availability_status === 'busy' ? 'text-yellow-400' :
                  'text-red-400'
                }`}>
                  {profile.availability_status?.charAt(0).toUpperCase() + profile.availability_status?.slice(1)}
                </p>
              </div>
            </div>
            {profile.tech_stack && profile.tech_stack.length > 0 && (
              <div className="mt-4">
                <p className="text-gray-400 text-sm mb-2">Tech Stack</p>
                <div className="flex flex-wrap gap-2">
                  {profile.tech_stack.map((tech) => (
                    <span
                      key={tech}
                      className="px-3 py-1 bg-purple-500/20 border border-purple-500/30 rounded-full text-purple-300 text-sm"
                    >
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Available Projects */}
        {profile?.vetting_status === 'approved' && (
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-white">Available Projects</h2>
              <a
                href="/developer/projects"
                className="text-purple-400 hover:text-purple-300 text-sm"
              >
                View All Projects
              </a>
            </div>

            {availableProjects.length > 0 ? (
              <div className="grid gap-4">
                {availableProjects.slice(0, 3).map((project) => (
                  <div
                    key={project.id}
                    className="bg-white/5 border border-white/10 rounded-lg p-4 hover:bg-white/10 transition-colors cursor-pointer"
                    onClick={() => router.push(`/developer/projects/${project.id}`)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h3 className="text-white font-medium mb-1">{project.title}</h3>
                        <p className="text-gray-400 text-sm line-clamp-2 mb-3">{project.description}</p>
                        <div className="flex items-center gap-4">
                          <span className="text-xs text-gray-500">
                            Budget: ${project.budget_amount?.toLocaleString() || 'TBD'}
                          </span>
                          <span className="text-xs text-gray-500">
                            Type: {project.budget_type}
                          </span>
                          {project.tech_stack && (
                            <div className="flex gap-1">
                              {project.tech_stack.slice(0, 3).map((tech) => (
                                <span key={tech} className="text-xs px-2 py-1 bg-blue-500/20 text-blue-400 rounded">
                                  {tech}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                      <button className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white text-sm font-medium rounded-lg transition-colors">
                        View & Bid
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12">
                <Briefcase className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                <p className="text-gray-400">No available projects matching your skills</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}